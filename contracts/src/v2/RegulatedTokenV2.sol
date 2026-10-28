// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "./TransactionFilterV2.sol";

/**
 * @title RegulatedTokenV2
 * @notice Reference GAP-regulated ERC-20 (the "tokenized security" of the local demo).
 * @dev Sender AND recipient are gated (GAP-H6): the sender needs a valid session for the
 *      transfer policy, the recipient a "receiving" session (a User Session under the
 *      deployment's receiving policy, same machinery, its own expiry cap). The TF is this
 *      contract's own per-contract filter; its ORDB's monitoredContract() points here.
 */
contract RegulatedTokenV2 is ERC20 {

    /**
     * WHAT THE GATE DOES AND DOES NOT PROMISE. `transfer`/`transferFrom` check the endpoints, `from`
     * and `to` must each hold a valid session, and that is the invariant the design rests on: an
     * asset never comes to rest with a non-compliant party.
     *
     * It is NOT "only compliant parties move the asset". `approve` is ungated and `transferFrom` does
     * not gate `msg.sender`, so a compliant holder can delegate spending authority to an unsessioned
     * spender, who can then move the holder's balance between two compliant endpoints. Gating the
     * spender would be a different and stronger claim; this contract does not make it, and the
     * distinction is easy to read past.
     */
    TransactionFilterV2 public immutable transactionFilter;
    address public admin;

    constructor(string memory name_, string memory symbol_, address _tf, address _admin)
        ERC20(name_, symbol_)
    {
        require(_tf != address(0) && _admin != address(0), "RT: zero addr");
        transactionFilter = TransactionFilterV2(_tf);
        admin = _admin;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == admin, "RT: not admin");
        _mint(to, amount);
    }

    // GAP-H6: both sides of a transfer are gated, with the REAL selector (the old _update gate
    // could only ever see transfer.selector, so transferFrom could never carry a
    // distinct policy). Mint is an admin distribution exemption (documented); burn is ungated.
    function transfer(address to, uint256 value) public override returns (bool) {
        _requireCompliant(this.transfer.selector, msg.sender, to);
        return super.transfer(to, value);
    }

    function transferFrom(address from, address to, uint256 value) public override returns (bool) {
        _requireCompliant(this.transferFrom.selector, from, to);
        return super.transferFrom(from, to, value);
    }

    function _requireCompliant(bytes4 selector, address from, address to) private view {
        require(transactionFilter.check(selector, from, address(0)), "RT: sender not compliant");
        require(transactionFilter.checkRecipient(selector, to), "RT: recipient not compliant");
    }
}
