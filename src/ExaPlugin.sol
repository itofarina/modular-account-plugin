// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import { BasePlugin } from "@alchemy/modular-account/plugins/BasePlugin.sol";
import { IPluginExecutor } from "@alchemy/modular-account/interfaces/IPluginExecutor.sol";
import { UserOperation } from "@alchemy/modular-account/interfaces/erc4337/UserOperation.sol";
import {
  ManifestFunction,
  ManifestAssociatedFunctionType,
  ManifestAssociatedFunction,
  PluginManifest,
  PluginMetadata
} from "@alchemy/modular-account/interfaces/IPlugin.sol";
import { IMultiOwnerPlugin } from "@alchemy/modular-account/plugins/owner/IMultiOwnerPlugin.sol";
import {
  AssociatedLinkedListSet,
  AssociatedLinkedListSetLib
} from "@alchemy/modular-account/libraries/AssociatedLinkedListSetLib.sol";
import {
  SetValue, SIG_VALIDATION_PASSED, SIG_VALIDATION_FAILED
} from "@alchemy/modular-account/libraries/Constants.sol";
import { CastLib } from "@alchemy/modular-account/helpers/CastLib.sol";
import { IStandardExecutor } from "@alchemy/modular-account/interfaces/IStandardExecutor.sol";
import {
  UpgradeableModularAccount, UUPSUpgradeable
} from "@alchemy/modular-account/account/UpgradeableModularAccount.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";
import { Auditor, Market, ERC20 } from "@exactly/protocol/contracts/Market.sol";

/// @title Exa Plugin
/// @author Exactly
contract ExaPlugin is BasePlugin, AccessControl {
  using AssociatedLinkedListSetLib for AssociatedLinkedListSet;
  using SafeTransferLib for ERC20;
  using ECDSA for bytes32;

  // metadata used by the pluginMetadata() method down below
  string public constant NAME = "Account Plugin";
  string public constant VERSION = "0.0.1";
  string public constant AUTHOR = "Exactly";
  bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");

  Auditor public immutable auditor;
  AssociatedLinkedListSet internal _owners;

  constructor(Auditor auditor_) {
    auditor = auditor_;

    Market[] memory markets = auditor.allMarkets();
    for (uint256 i = 0; i < markets.length; ++i) {
      approve(markets[i]);
    }

    _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
  }

  // this is a constant used in the manifest, to reference our only dependency: the multi owner plugin
  // since it is the first, and only, plugin the index 0 will reference the multi owner plugin
  // we can use this to tell the modular account that we should use the multi owner plugin to validate our user op
  // in other words, we'll say "make sure the person calling execution functions is an owner of the account using the multiowner plugin"
  uint256 internal constant _MANIFEST_DEPENDENCY_INDEX_OWNER_USER_OP_VALIDATION = 0;

  bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
  bytes4 internal constant _1271_MAGIC_VALUE_FAILURE = 0xffffffff;
  bytes32 private constant MODULAR_ACCOUNT_TYPEHASH = keccak256("AlchemyModularAccountMessage(bytes message)");
  bytes32 private constant _TYPE_HASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
  bytes32 private constant _HASHED_NAME = keccak256(bytes(NAME));
  bytes32 private constant _HASHED_VERSION = keccak256(bytes(VERSION));
  bytes32 private immutable _SALT = bytes32(bytes20(address(this)));

  function checkIsMarket(Market market) public view {
    (,,, bool isMarket,) = auditor.markets(market);
    if (!isMarket) revert("ExaPlugin: not a market");
  }

  /// @notice Approves the Market to spend the contract's balance of the underlying asset.
  /// @dev The Market must be listed by the Auditor in order to be valid for approval.
  /// @param market The Market to spend the contract's balance.
  function approve(Market market) public onlyMarket(market) {
    market.asset().safeApprove(address(market), type(uint256).max);
  }

  modifier onlyMarket(Market market) {
    checkIsMarket(market);
    _;
  }

  // /// @inheritdoc IERC1271
  // /// @dev The signature is valid if it is signed by one of the owners' private key
  // /// (if the owner is an EOA) or if it is a valid ERC-1271 signature from one of the
  // /// owners (if the owner is a contract). Note that unlike the signature
  // /// validation used in `validateUserOp`, this does not wrap the digest in
  // /// an "Ethereum Signed Message" envelope before checking the signature in
  // /// the EOA-owner case.
  // function isValidSignature(
  //     bytes32 digest,
  //     bytes memory signature
  // ) public view override returns (bytes4) {
  //     bytes32 messageHash = getMessageHash(msg.sender, abi.encode(digest));

  //     // try to recover through ECDSA
  //     (address signer, ECDSA.RecoverError error) = ECDSA.tryRecover(
  //         messageHash,
  //         signature
  //     );
  //     if (
  //         error == ECDSA.RecoverError.NoError &&
  //         _owners.contains(msg.sender, CastLib.toSetValue(signer))
  //     ) {
  //         return _1271_MAGIC_VALUE;
  //     }

  //     if (
  //         _isValidERC1271OwnerTypeSignature(
  //             msg.sender,
  //             messageHash,
  //             signature
  //         )
  //     ) {
  //         return _1271_MAGIC_VALUE;
  //     }

  //     return _1271_MAGIC_VALUE_FAILURE;
  // }

  // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  // ┃    Execution functions    ┃
  // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

  // in the manifest we define it as an execution function,
  // and we specify the validation function for the user op targeting this function
  function enterMarket(Market market) external {
    auditor.enterMarket(market);
  }

  function deposit(Market market, uint256 amount) external onlyMarket(market) {
    market.asset().safeTransferFrom(msg.sender, address(this), amount);
    market.deposit(amount, msg.sender);
  }

  // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  // ┃    Plugin interface functions    ┃
  // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

  /// @inheritdoc BasePlugin
  /// @dev The owner array cannot have 0 or duplicated addresses.
  function _onInstall(bytes calldata data) internal override isNotInitialized(msg.sender) {
    (address[] memory initialOwners) = abi.decode(data, (address[]));
    if (initialOwners.length == 0) {
      revert EmptyOwnersNotAllowed();
    }
    _addOwnersOrRevert(_owners, msg.sender, initialOwners);

    emit OwnerUpdated(msg.sender, initialOwners, new address[](0));
  }

  /// @inheritdoc BasePlugin
  function onUninstall(bytes calldata) external override {
    address[] memory ownersToRemove = ownersOf(msg.sender);
    emit OwnerUpdated(msg.sender, new address[](0), ownersToRemove);
    _owners.clear(msg.sender);
  }

  /// @inheritdoc BasePlugin
  /// @dev Since owner can be an ERC-1271 compliant contract, we won't know the format of the signatures.
  /// Therefore, any invalid signature are treated as mismatched signatures in the ERC-4337 context unless
  /// reverted in ERC-1271 owner signature validation.
  function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
    external
    view
    override
    returns (uint256)
  {
    if (functionId == uint8(FunctionId.USER_OP_VALIDATION_OWNER)) {
      (address signer, ECDSA.RecoverError error) = userOpHash.toEthSignedMessageHash().tryRecover(userOp.signature);
      if (error == ECDSA.RecoverError.NoError && isOwnerOf(msg.sender, signer)) {
        return SIG_VALIDATION_PASSED;
      }

      if (_isValidERC1271OwnerTypeSignature(msg.sender, userOpHash, userOp.signature)) {
        return SIG_VALIDATION_PASSED;
      }

      return SIG_VALIDATION_FAILED;
    }

    revert NotImplemented(msg.sig, functionId);
  }

  /// @inheritdoc BasePlugin
  function runtimeValidationFunction(uint8 functionId, address sender, uint256, bytes calldata) external view override {
    if (functionId == uint8(FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)) {
      // Validate that the sender is an owner of the account, or self.
      if (sender != msg.sender && !isOwnerOf(msg.sender, sender)) {
        revert NotAuthorized();
      }
      return;
    }
    revert NotImplemented(msg.sig, functionId);
  }

  /// @inheritdoc BasePlugin
  function pluginManifest() external pure override returns (PluginManifest memory) {
    PluginManifest memory manifest;

    manifest.executionFunctions = new bytes4[](4);
    manifest.executionFunctions[0] = this.updateOwners.selector;
    manifest.executionFunctions[1] = this.eip712Domain.selector;
    manifest.executionFunctions[2] = this.isValidSignature.selector;
    manifest.executionFunctions[3] = this.deposit.selector;

    ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
      functionType: ManifestAssociatedFunctionType.SELF,
      functionId: uint8(FunctionId.USER_OP_VALIDATION_OWNER),
      dependencyIndex: 0 // Unused.
     });

    // Update Modular Account's native functions to use userOpValidationFunction provided by this plugin
    // The view functions `isValidSignature` and `eip712Domain` are excluded from being assigned a user
    // operation validation function since they should only be called via the runtime path.
    manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](6);
    manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
      executionSelector: this.updateOwners.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
      executionSelector: IStandardExecutor.execute.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[2] = ManifestAssociatedFunction({
      executionSelector: IStandardExecutor.executeBatch.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[3] = ManifestAssociatedFunction({
      executionSelector: UpgradeableModularAccount.installPlugin.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[4] = ManifestAssociatedFunction({
      executionSelector: UpgradeableModularAccount.uninstallPlugin.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[5] = ManifestAssociatedFunction({
      executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
      associatedFunction: ownerUserOpValidationFunction
    });

    ManifestFunction memory ownerOrSelfRuntimeValidationFunction = ManifestFunction({
      functionType: ManifestAssociatedFunctionType.SELF,
      functionId: uint8(FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF),
      dependencyIndex: 0 // Unused.
     });
    ManifestFunction memory alwaysAllowFunction = ManifestFunction({
      functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
      functionId: 0, // Unused.
      dependencyIndex: 0 // Unused.
     });

    // Update Modular Account's native functions to use runtimeValidationFunction provided by this plugin
    manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](8);
    manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
      executionSelector: this.updateOwners.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
      executionSelector: IStandardExecutor.execute.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
      executionSelector: IStandardExecutor.executeBatch.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[3] = ManifestAssociatedFunction({
      executionSelector: UpgradeableModularAccount.installPlugin.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[4] = ManifestAssociatedFunction({
      executionSelector: UpgradeableModularAccount.uninstallPlugin.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[5] = ManifestAssociatedFunction({
      executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });
    manifest.runtimeValidationFunctions[6] = ManifestAssociatedFunction({
      executionSelector: this.isValidSignature.selector,
      associatedFunction: alwaysAllowFunction
    });
    manifest.runtimeValidationFunctions[7] = ManifestAssociatedFunction({
      executionSelector: this.eip712Domain.selector,
      associatedFunction: alwaysAllowFunction
    });

    manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](1);
    manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
      executionSelector: this.deposit.selector,
      associatedFunction: ownerOrSelfRuntimeValidationFunction
    });

    manifest.preRuntimeValidationHooks = new ManifestAssociatedFunction[](1);
    manifest.preRuntimeValidationHooks[0] = ManifestAssociatedFunction({
      executionSelector: this.deposit.selector,
      associatedFunction: ManifestFunction({
        functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
        functionId: 0,
        dependencyIndex: 0
      })
    });

    return manifest;
  }

  /// @inheritdoc BasePlugin
  function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
    PluginMetadata memory metadata;
    metadata.name = NAME;
    metadata.version = VERSION;
    metadata.author = AUTHOR;
    return metadata;
  }

  function isOwnerOf(address account, address ownerToCheck) public view returns (bool) {
    return _owners.contains(account, CastLib.toSetValue(ownerToCheck));
  }

  function ownersOf(address account) public view returns (address[] memory) {
    return CastLib.toAddressArray(_owners.getAll(account));
  }

  function _addOwnersOrRevert(
    AssociatedLinkedListSet storage ownerSet,
    address associated,
    address[] memory ownersToAdd
  ) private {
    uint256 length = ownersToAdd.length;
    for (uint256 i = 0; i < length; ++i) {
      // Catches address(0), duplicated addresses
      if (!ownerSet.tryAdd(associated, CastLib.toSetValue(ownersToAdd[i]))) {
        revert InvalidOwner(ownersToAdd[i]);
      }
    }
  }

  function _isValidERC1271OwnerTypeSignature(address associated, bytes32 digest, bytes memory signature)
    private
    view
    returns (bool)
  {
    address[] memory owners_ = ownersOf(associated);
    uint256 length = owners_.length;
    for (uint256 i = 0; i < length; ++i) {
      if (SignatureChecker.isValidERC1271SignatureNow(owners_[i], digest, signature)) {
        return true;
      }
    }
    return false;
  }

  /// @inheritdoc BasePlugin
  function _isInitialized(address account) internal view override returns (bool) {
    return !_owners.isEmpty(account);
  }

  function updateOwners(address[] memory ownersToAdd, address[] memory ownersToRemove) public isInitialized(msg.sender) {
    _removeOwnersOrRevert(_owners, msg.sender, ownersToRemove);
    _addOwnersOrRevert(_owners, msg.sender, ownersToAdd);

    if (_owners.isEmpty(msg.sender)) {
      revert EmptyOwnersNotAllowed();
    }

    emit OwnerUpdated(msg.sender, ownersToAdd, ownersToRemove);
  }

  function _removeOwnersOrRevert(
    AssociatedLinkedListSet storage ownerSet,
    address associated,
    address[] memory ownersToRemove
  ) private {
    uint256 length = ownersToRemove.length;
    for (uint256 i = 0; i < length; ++i) {
      if (!ownerSet.tryRemove(associated, CastLib.toSetValue(ownersToRemove[i]))) {
        revert OwnerDoesNotExist(ownersToRemove[i]);
      }
    }
  }

  function isValidSignature(bytes32 digest, bytes memory signature) public view returns (bytes4) {
    bytes32 messageHash = getMessageHash(msg.sender, abi.encode(digest));

    // try to recover through ECDSA
    (address signer, ECDSA.RecoverError error) = ECDSA.tryRecover(messageHash, signature);
    if (error == ECDSA.RecoverError.NoError && _owners.contains(msg.sender, CastLib.toSetValue(signer))) {
      return _1271_MAGIC_VALUE;
    }

    if (_isValidERC1271OwnerTypeSignature(msg.sender, messageHash, signature)) {
      return _1271_MAGIC_VALUE;
    }

    return _1271_MAGIC_VALUE_FAILURE;
  }

  function encodeMessageData(address account, bytes memory message) public view returns (bytes memory) {
    bytes32 messageHash = keccak256(abi.encode(MODULAR_ACCOUNT_TYPEHASH, keccak256(message)));
    return abi.encodePacked("\x19\x01", _domainSeparator(account), messageHash);
  }

  function getMessageHash(address account, bytes memory message) public view returns (bytes32) {
    return keccak256(encodeMessageData(account, message));
  }

  function _domainSeparator(address account) internal view returns (bytes32) {
    return keccak256(abi.encode(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION, block.chainid, account, _SALT));
  }

  function eip712Domain()
    public
    view
    returns (
      bytes1 fields,
      string memory name,
      string memory version,
      uint256 chainId,
      address verifyingContract,
      bytes32 salt,
      uint256[] memory extensions
    )
  {
    return (
      hex"1f", // 11111 indicate salt field is also used
      NAME,
      VERSION,
      block.chainid,
      msg.sender,
      _SALT,
      new uint256[](0)
    );
  }

  function supportsInterface(bytes4 interfaceId) public view override(AccessControl, BasePlugin) returns (bool) {
    return super.supportsInterface(interfaceId);
  }

  /// @notice This event is emitted when owners of the account are updated.
  /// @param account The account whose ownership changed.
  /// @param addedOwners The address array of added owners.
  /// @param removedOwners The address array of removed owners.
  event OwnerUpdated(address indexed account, address[] addedOwners, address[] removedOwners);
}

error InvalidOwner(address owner);
error EmptyOwnersNotAllowed();
error NotAuthorized();
error OwnerDoesNotExist(address owner);

enum FunctionId {
  RUNTIME_VALIDATION_OWNER_OR_SELF, // require owner or self access
  USER_OP_VALIDATION_OWNER // require owner access

}
