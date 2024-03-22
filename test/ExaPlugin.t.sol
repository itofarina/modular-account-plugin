// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test } from "forge-std/Test.sol";
import { EntryPoint } from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { UpgradeableModularAccount } from "@alchemy/modular-account/src/account/UpgradeableModularAccount.sol";
import { IEntryPoint } from "@alchemy/modular-account/src/interfaces/erc4337/IEntryPoint.sol";
import { UserOperation } from "@alchemy/modular-account/src/interfaces/erc4337/UserOperation.sol";
import { MultiOwnerModularAccountFactory } from
  "@alchemy/modular-account/src/factory/MultiOwnerModularAccountFactory.sol";
import { MultiOwnerPlugin } from "@alchemy/modular-account/src/plugins/owner/MultiOwnerPlugin.sol";
import { IMultiOwnerPlugin } from "@alchemy/modular-account/src/plugins/owner/IMultiOwnerPlugin.sol";
import { FunctionReference } from "@alchemy/modular-account/src/interfaces/IPluginManager.sol";
import { FunctionReferenceLib } from "@alchemy/modular-account/src/helpers/FunctionReferenceLib.sol";

import { ExaPlugin, Auditor, Market } from "../src/ExaPlugin.sol";
import { InterestRateModel } from "@exactly/protocol/contracts/InterestRateModel.sol";
import { MockPriceFeed } from "@exactly/protocol/contracts/mocks/MockPriceFeed.sol";
import { ERC20, MockERC20 } from "solmate/src/test/utils/mocks/MockERC20.sol";

contract AccountTest is Test {
  using ECDSA for bytes32;

  IEntryPoint entryPoint;
  UpgradeableModularAccount account1;
  ExaPlugin exaPlugin;
  address owner1;
  uint256 owner1Key;
  address[] public owners;
  address payable beneficiary;
  address public keeper1;

  uint256 constant CALL_GAS_LIMIT = 1_000_000;
  uint256 constant VERIFICATION_GAS_LIMIT = 1_000_000;

  MockERC20 public asset;
  Market public market;
  Auditor public auditor;

  function setUp() public {
    auditor = Auditor(address(new ERC1967Proxy(address(new Auditor(18)), "")));
    auditor.initialize(Auditor.LiquidationIncentive(0.09e18, 0.01e18));
    vm.label(address(auditor), "Auditor");

    asset = new MockERC20("Mock asset", "MOCK", 18);
    market = Market(address(new ERC1967Proxy(address(new Market(asset, auditor)), "")));
    market.initialize(
      3,
      1e18,
      InterestRateModel(address(new MockInterestRateModel(0.1e18))),
      0.02e18 / uint256(1 days),
      1e17,
      0,
      0.0046e18,
      0.42e18
    );
    vm.label(address(market), "Market");

    auditor.enableMarket(market, new MockPriceFeed(18, 1e18), 0.8e18);

    // we'll be using the entry point so we can send a user operation through
    // in this case our plugin only accepts calls to enter market via user operations so this is essential
    entryPoint = IEntryPoint(address(new EntryPoint()));

    // our modular smart contract account will be installed with the multi owner plugin
    // so we have a way to determine who is authorized to do things on this account
    // we'll use this plugin's validation for our enter market function
    MultiOwnerPlugin multiOwnerPlugin = new MultiOwnerPlugin();
    MultiOwnerModularAccountFactory factory = new MultiOwnerModularAccountFactory(
      address(this),
      address(multiOwnerPlugin),
      address(new UpgradeableModularAccount(entryPoint)),
      keccak256(abi.encode(multiOwnerPlugin.pluginManifest())),
      entryPoint
    );

    // the beneficiary of the fees at the entry point
    beneficiary = payable(makeAddr("beneficiary"));

    // create a single owner for this account and provide the address to our modular account
    // we'll also add ether to our account to pay for gas fees
    (owner1, owner1Key) = makeAddrAndKey("owner1");
    owners = new address[](1);
    owners[0] = owner1;
    account1 = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));
    vm.deal(address(account1), 100 ether);

    (keeper1,) = makeAddrAndKey("keeper1");

    // create our account plugin and grab the manifest hash so we can install it
    // note: plugins are singleton contracts, so we only need to deploy them once
    exaPlugin = new ExaPlugin(auditor);
    bytes32 manifestHash = keccak256(abi.encode(exaPlugin.pluginManifest()));

    // we will have a single function dependency for our account contract: the multi owner user op validation
    // we'll use this to ensure that only an owner can sign a user operation that can successfully enter market
    FunctionReference[] memory dependencies = new FunctionReference[](1);
    dependencies[0] =
      FunctionReferenceLib.pack(address(multiOwnerPlugin), uint8(IMultiOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));

    // install this plugin on the account as the owner
    vm.prank(owner1);
    account1.installPlugin({
      plugin: address(exaPlugin),
      manifestHash: manifestHash,
      pluginInstallData: "0x",
      dependencies: dependencies
    });

    asset.mint(address(account1), 1_000_000e18);
  }

  function test_EnterMarket() external {
    uint256 marketsIndexesInitial = auditor.accountMarkets(address(account1));

    // TODO compare with entered market's index
    emit log_named_uint("marketsIndexesInitial", marketsIndexesInitial);

    // create a user operation which has the calldata to specify we'd like to enter market
    UserOperation memory userOp = UserOperation({
      sender: address(account1),
      nonce: 0,
      initCode: "",
      callData: abi.encodeCall(ExaPlugin.enterMarket, (market)),
      callGasLimit: CALL_GAS_LIMIT,
      verificationGasLimit: VERIFICATION_GAS_LIMIT,
      preVerificationGas: 0,
      maxFeePerGas: 2,
      maxPriorityFeePerGas: 1,
      paymasterAndData: "",
      signature: ""
    });

    // sign this user operation with the owner, otherwise it will revert due to the multiowner validation
    bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
    userOp.signature = abi.encodePacked(r, s, v);

    // send our single user operation to enter market
    UserOperation[] memory userOps = new UserOperation[](1);
    userOps[0] = userOp;
    entryPoint.handleOps(userOps, beneficiary);

    // check that market was entered
    uint256 marketsIndexes = auditor.accountMarkets(address(account1));

    // TODO compare with entered market's index
    emit log_named_uint("marketsIndexes", marketsIndexes);
  }

  function signOp(UserOperation memory userOp, uint256 key) internal returns (UserOperation memory) {
    bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, userOpHash.toEthSignedMessageHash());
    userOp.signature = abi.encodePacked(r, s, v);
    return userOp;
  }

  function test_Deposit() external {
    vm.prank(owner1);
    // vm.prank(keeper1);
    account1.execute(address(asset), 0, abi.encodeCall(ERC20.approve, (address(exaPlugin), type(uint256).max)));

    uint256 amount = 100 ether;

    UserOperation[] memory userOps = new UserOperation[](1);
    userOps[0] = signOp(
      UserOperation({
        sender: address(account1),
        nonce: 0,
        initCode: "",
        callData: abi.encodeCall(ExaPlugin.deposit, (market, amount)),
        callGasLimit: CALL_GAS_LIMIT,
        verificationGasLimit: VERIFICATION_GAS_LIMIT,
        preVerificationGas: 0,
        maxFeePerGas: 2,
        maxPriorityFeePerGas: 1,
        paymasterAndData: "",
        signature: ""
      }),
      owner1Key
    );
    entryPoint.handleOps(userOps, beneficiary);

    assertEq(market.balanceOf(address(account1)), amount);
  }
}

contract MockInterestRateModel {
  uint256 public rate;

  constructor(uint256 rate_) {
    rate = rate_;
  }

  function floatingRate(uint256) external view returns (uint256) {
    return rate;
  }

  function floatingRate(uint256, uint256) external view returns (uint256) {
    return rate;
  }

  function fixedRate(uint256, uint256, uint256, uint256, uint256) external view returns (uint256) {
    return rate;
  }

  function fixedBorrowRate(uint256 maturity, uint256, uint256, uint256, uint256) external view returns (uint256) {
    return (rate * (maturity - block.timestamp)) / 365 days;
  }

  function setRate(uint256 newRate) public {
    rate = newRate;
  }
}
