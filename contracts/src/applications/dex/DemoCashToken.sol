// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

// UNAUDITED REFERENCE IMPLEMENTATION, NOT FOR PRODUCTION. See SECURITY.md.

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @notice The ungated cash leg of the demo pool. A security trades against something; that
 *         something is not the subject of the compliance story and is deliberately a plain ERC-20.
 * @dev Mintable by its deployer so a local demo can fund both sides of a pool. Not a stablecoin,
 *      not a claim on anything, and not gated, if the cash leg were also gated, a failure could be
 *      attributed to the wrong token and the demo would prove less, not more.
 */
contract DemoCashToken is ERC20 {
    address public immutable admin;

    error CashNotAdmin();

    constructor(address admin_) ERC20("Demo Cash (USD)", "dUSD") {
        admin = admin_;
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        if (msg.sender != admin) revert CashNotAdmin();
        _mint(to, amount);
    }
}
