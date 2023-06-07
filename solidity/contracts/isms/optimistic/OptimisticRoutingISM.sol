// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

// ============ External Imports ============
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
// ============ Internal Imports ============
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {AbstractOptimismIsm} from "./AbstractOptimisimIsm.sol";

error PreVerificationFailed();
error FraudWindowHasNotElapsed();
error TransactionIsFlaggedFraudulent();

/**
 * @title OptimisticISM
 * @dev A contract for an Optimistic Interchain Security Module.
 * It acts as a routing mechanism to different submodules based on incoming messages.
 * It verifies the messages using the submodules and handles fraudulent transactions.
 */
contract OptimisticISM is AbstractOptimismIsm, OwnableUpgradeable {
    // ============ Public Storage ============
    uint256 public fraudulentTime;

    mapping(address => uint16) public fraudulentSubModules;

    mapping(bytes => address) public submodules;

    mapping(address => bool) public watchers;

    uint16 public numOfWatchers;

    uint16 public maxNumOfFlag;

    modifier onlyWatchers() {
        require(watchers[msg.sender] == true, "Only authorized by watchers");
        _;
    }

    /**
     * @dev Initializes the contract with the given owner and maximum number of flags.
     * @param _owner The owner of the contract.
     * @param _maxNumOfFlag The maximum number of flags allowed for a submodule.
     */
    function initialize(address _owner, uint16 _maxNumOfFlag)
        public
        initializer
    {
        __Ownable_init();
        _transferOwnership(_owner);
        maxNumOfFlag = _maxNumOfFlag;
    }

    /**
     * @dev Sets the maximum number of flags allowed for a submodule.
     * Only the owner can call this function.
     * @param _maxFlag The maximum number of flags allowed.
     */
    function setMaxNumOfFlag(uint16 _maxFlag) external onlyOwner {
        maxNumOfFlag = _maxFlag;
    }

    /**
     * @dev Sets the submodule for a specific message.
     * Only the owner can call this function.
     * @param _message The message to set the submodule for.
     * @param _submodule The address of the submodule contract.
     */
    function setSubmodule(bytes calldata _message, address _submodule)
        external
        onlyOwner
    {
        submodules[_message] = _submodule;
    }

    /**
     * @dev Sets the authorized watcher addresses.
     * Only the owner can call this function.
     * @param _address The address of the watcher to set.
     */
    function setWatchers(address _address) external onlyOwner {
        if (watchers[_address] == false) {
            watchers[_address] = true;
            numOfWatchers += 1;
        }
    }

    /**
     * @dev Sets the fraudulent time for marking transactions as fraudulent.
     * Only the owner can call this function.
     * @param _time The fraudulent time to set.
     */
    function setFraudulentTime(uint256 _time) external onlyOwner {
        fraudulentTime = _time;
    }

    /**
     * @dev Routes the message to the corresponding submodule based on the message type.
     * @param _message The message to route.
     * @return The corresponding Interchain Security Module contract.
     */
    function route(bytes calldata _message)
        public
        view
        virtual
        override
        returns (IInterchainSecurityModule)
    {
        IInterchainSecurityModule _submodule = IInterchainSecurityModule(
            submodules[_message]
        );
        require(
            address(_submodule) != address(0),
            "No ISM found for origin domain"
        );
        return _submodule;
    }

    /**
     * @dev Verifies the message using the corresponding submodule and handles fraudulent transactions.
     * @param _metadata The metadata of the message.
     * @param _message The message to verify.
     * @return A boolean indicating the verification result.
     */
    function verify(bytes calldata _metadata, bytes calldata _message)
        public
        virtual
        override
        returns (bool)
    {
        if (preVerify(_metadata, _message) == false)
            revert PreVerificationFailed();
        if (fraudulentSubModules[submodules[_message]] > maxNumOfFlag)
            revert TransactionIsFlaggedFraudulent();
        if (block.timestamp < fraudulentTime) revert FraudWindowHasNotElapsed();
        return true;
    }

    /**
     * @dev Pre-verifies the message using the corresponding submodule.
     * @param _metadata The metadata of the message.
     * @param _message The message to pre-verify.
     * @return A boolean indicating the pre-verification result.
     */
    function preVerify(bytes calldata _metadata, bytes calldata _message)
        public
        returns (bool)
    {
        IInterchainSecurityModule _ism = IInterchainSecurityModule(
            submodules[_message]
        );
        return _ism.verify(_metadata, _message);
    }

    /**
     * @dev Marks a submodule as fraudulent.
     * Watchers can call this function to flag a specific submodule as fraudulent.
     * @param _submodule The address of the submodule to mark as fraudulent.
     */
    function markFraudulent(address _submodule) external onlyWatchers {
        require(
            fraudulentTime > block.timestamp,
            "Time to mark fraudulent has elapsed"
        );
        fraudulentSubModules[_submodule] += 1;
    }

    /**
     * @dev Retrieves the submodule for a specific message.
     * @param _message The message to retrieve the submodule for.
     * @return The corresponding Interchain Security Module contract.
     */
    function submodule(bytes calldata _message)
        external
        view
        returns (IInterchainSecurityModule)
    {
        return IInterchainSecurityModule(submodules[_message]);
    }
}
