// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import { BasePlugin } from "@alchemy/modular-account/src/plugins/BasePlugin.sol";
import { IPluginExecutor } from "@alchemy/modular-account/src/interfaces/IPluginExecutor.sol";
import {
  ManifestFunction,
  ManifestAssociatedFunctionType,
  ManifestAssociatedFunction,
  PluginManifest,
  PluginMetadata
} from "@alchemy/modular-account/src/interfaces/IPlugin.sol";
import { IMultiOwnerPlugin } from "@alchemy/modular-account/src/plugins/owner/IMultiOwnerPlugin.sol";

import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";
import { Auditor, Market, ERC20 } from "@exactly/protocol/contracts/Market.sol";

/// @title Exa Plugin
/// @author Exactly
contract ExaPlugin is BasePlugin {
  using SafeTransferLib for ERC20;

  // metadata used by the pluginMetadata() method down below
  string public constant NAME = "Account Plugin";
  string public constant VERSION = "0.0.1";
  string public constant AUTHOR = "Exactly";

  constructor(Auditor auditor_) {
    auditor = auditor_;

    Market[] memory markets = auditor.allMarkets();
    for (uint256 i = 0; i < markets.length; ++i) {
      approve(markets[i]);
    }
  }

  // this is a constant used in the manifest, to reference our only dependency: the multi owner plugin
  // since it is the first, and only, plugin the index 0 will reference the multi owner plugin
  // we can use this to tell the modular account that we should use the multi owner plugin to validate our user op
  // in other words, we'll say "make sure the person calling execution functions is an owner of the account using the multiowner plugin"
  uint256 internal constant _MANIFEST_DEPENDENCY_INDEX_OWNER_USER_OP_VALIDATION = 0;

  /*
     * Note to Developer:
     * If you're using storage during validation, you need to use "associated storage".
     * ERC 7562 defines the associated storage rules for ERC 4337 accounts.
     * See: https://eips.ethereum.org/EIPS/eip-7562#validation-rules
     *
     * Plugins need to follow this definition for bundlers to accept user ops targeting their validation functions.
     * In this case, "count" is only used in an execution function, but nonetheless, it's worth noting
     * that a mapping from the account address is considered associated storage.
     */
  Auditor public immutable auditor;

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
  function onInstall(bytes calldata) external pure override { }

  /// @inheritdoc BasePlugin
  function onUninstall(bytes calldata) external pure override { }

  /// @inheritdoc BasePlugin
  function pluginManifest() external pure override returns (PluginManifest memory) {
    PluginManifest memory manifest;

    // since we are using the modular account, we will specify one depedency
    // which will be the multiowner plugin
    // you can find this depedency specified in the installPlugin call in the tests
    manifest.dependencyInterfaceIds = new bytes4[](1);
    manifest.dependencyInterfaceIds[0] = type(IMultiOwnerPlugin).interfaceId;

    // we define execution functions on the manifest as something that can be called during execution
    manifest.executionFunctions = new bytes4[](2);
    manifest.executionFunctions[0] = this.enterMarket.selector;
    manifest.executionFunctions[1] = this.deposit.selector;

    // you can think of ManifestFunction as a reference to a function somewhere,
    // we want to say "use this function" for some purpose - in this case,
    // we'll be using the user op validation function from the multi owner dependency
    // and this is specified by the depdendency index
    ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
      functionType: ManifestAssociatedFunctionType.DEPENDENCY,
      functionId: 0, // unused since it's a dependency
      dependencyIndex: _MANIFEST_DEPENDENCY_INDEX_OWNER_USER_OP_VALIDATION
    });

    // links together the enterMarket function with the multi owner user op validation
    // this basically says "use this user op validation function and make sure everythings okay before calling enterMarket"
    // this will ensure that only an owner of the account can call enterMarket
    manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](2);
    manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
      executionSelector: this.enterMarket.selector,
      associatedFunction: ownerUserOpValidationFunction
    });
    manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
      executionSelector: this.deposit.selector,
      associatedFunction: ownerUserOpValidationFunction
    });

    // here, we will always deny runtime calls to the enterMarket function as we will only call it through user ops
    // this avoids a potential issue where a future plugin may define
    // a runtime validation function for it and unauthorized calls may occur due to that
    manifest.preRuntimeValidationHooks = new ManifestAssociatedFunction[](2);
    manifest.preRuntimeValidationHooks[0] = ManifestAssociatedFunction({
      executionSelector: this.enterMarket.selector,
      associatedFunction: ManifestFunction({
        functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
        functionId: 0,
        dependencyIndex: 0
      })
    });
    manifest.preRuntimeValidationHooks[1] = ManifestAssociatedFunction({
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
}
