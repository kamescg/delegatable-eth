pragma solidity ^0.8.13;
//SPDX-License-Identifier: MIT

import "./Delegatable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
    _______    ____  ___   ____             __  __              __                    __
   / ____/ |  / /  |/  /  / __ )_________  / /_/ /_  ___  _____/ /_  ____  ____  ____/ /
  / __/  | | / / /|_/ /  / __  / ___/ __ \/ __/ __ \/ _ \/ ___/ __ \/ __ \/ __ \/ __  / 
 / /___  | |/ / /  / /  / /_/ / /  / /_/ / /_/ / / /  __/ /  / / / / /_/ / /_/ / /_/ /  
/_____/  |___/_/  /_/  /_____/_/   \____/\__/_/ /_/\___/_/  /_/ /_/\____/\____/\__,_/   
                                                        all for one. and one for all.

🗺️ Overview:
The TransctionMetadataRegistry contract is designed to curate transaction-metadata lists.
Lists include metadata about transaction execution. The metadata should educate users about
the transaction and its side-effects.

📜 Abstract:
The TransctionMetadataRegistry uses a "Web3 of Trust" model to enable data publishing.
Zones are a loosely coupled aggregation of EVM execution metdata. A deposit is required to start a Zone.
Owners of a Zone can issue root Certificates, which have the authority to publish metadata.
Root Certificates can delegate authority to other signing keys off-chain using Delegatable.sol

🏗️ Architecture:
Zones
  - Zone Authority 
    - Root Certificate
      - Publisher (Root or Branch Key)
        - Data
*/
contract TransctionMetadataRegistry is Ownable, Delegatable {

  /**
    @dev Zones are managed by a single Owner. 
         The zone owner can add and remove root certificates.
    @dev The authority should be a MultiSig managed by 5+ people.
    -----------------------------
    | Zone        | Authority   |
    | ----------- | ----------- |
    | 0x111...111 | 0xFfF...fFf |
    | 0x111...111 | 0xFfF...fFf |
    -----------------------------
  */
  mapping (bytes32 => address) zones;

  /**
    @dev Zones can contain N root certificates.
         Certificates have the authority to publish metadata.
    @dev Certificates can delegate authority to other signing keys off-chain.
    -------------------------------------------------
    | Zone        	| Root Certificate => Enabled 	|
    |-------------	|-----------------------------	|
    | 0x111...111 	| 0xFfF...fFf => true         	|
    | 0x111...111 	| 0xFfF...fFf => false        	|
    -------------------------------------------------
  */
  mapping (bytes32 => mapping(address => bool)) certificates;
  
  /**
    ---------------------------------------------
    | Contract     	| Method Signature => IPFS 	|
    |--------------	|--------------------------	|
    | 0x000...0000 	| 0x11223344 => ipfs://    	|
    | 0x000...0000 	| 0x11223344 => ipfs://    	|
    ---------------------------------------------
  */
  mapping(bytes32 => mapping(address => mapping(bytes4 => string))) metadata;

  /* ================================================================================ */
  /* Initialization                                                                   */
  /* ================================================================================ */
  event Zone(bytes32 zone, address authority);
  event Certificate(bytes32 zone, address authority, bool permission);
  event Meta(bytes32 zone, address location, bytes4 method, string uri);

  constructor(address owner) 
    Delegatable("TransctionMetadataRegistry", "1") 
  {
    require(owner != address(0), "TMR:owner-not-zero");
    require(owner != address(this), "TMR:owner-not-self");
  }

  modifier isAuthorized(bytes32 zone) {
    require(certificates[zone][_msgSender()], "TMR:not-authorized");
    _;
  }

  /* ================================================================================ */
  /* External Functions                                                               */
  /* ================================================================================ */
  function open(bytes32 zone, address authority) payable external {
    require(msg.value > 1 ether, "TMR:zone-fee-required");
    require(zones[zone] == address(0), "TMR:zone-exists");
    zones[zone] = authority;
    emit Zone(zone, authority);
  }

  function authorize(bytes32 zone, address root, bool permission) external {
    require(zones[zone] == msg.sender, "TMR:not-zone-owner");
    certificates[zone][root] = permission;
    emit Certificate(zone, root, permission);
  }

  function set(bytes32 zone, address location, bytes4 method, string calldata uri) isAuthorized(zone) external {
    metadata[zone][location][method] = uri;
    emit Meta(zone, location, method, uri);
  }
  
  function get(bytes32 zone, address location, bytes4 method) external returns (string memory){
    return metadata[zone][location][method];
  }

  /**
    @dev Owner can rewrite ALL zone metadata i.e. backstop for bad actors.
  */
  function update(bytes32 zone, address location, bytes4 method, string calldata uri) onlyOwner external {
    metadata[zone][location][method] = uri;
    emit Meta(zone, location, method, uri);
  }
  
  function collect() onlyOwner external {
    (bool success, ) = _msgSender().call{value:address(this).balance}("");
    require(success, "Transfer failed.");
  }

  /* ================================================================================ */
  /* Internal Functions                                                               */
  /* ================================================================================ */

  /// @inheritdoc Delegatable
  function _msgSender () internal view override(Delegatable, Context) returns (address sender) {
    if(msg.sender == address(this)) {
      bytes memory array = msg.data;
      uint256 index = msg.data.length;
      assembly {
        // Load the 32 bytes word from memory with the address on the lower 20 bytes, and mask those.
        sender := and(mload(add(array, index)), 0xffffffffffffffffffffffffffffffffffffffff)
      }
    } else {
      sender = msg.sender;
    }
    return sender;
  }
}
