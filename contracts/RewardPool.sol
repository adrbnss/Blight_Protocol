// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract RewardPool is Ownable {
    IERC20 public token;
    address public tokenAddress;

    constructor(address _token) {
        token = IERC20(_token);
        tokenAddress = _token;
    }

    function distributeShares(address[] memory holders) external {
        require(msg.sender == tokenAddress, "Only token contract can call this function");
        uint256 balance = token.balanceOf(address(this));
        if (balance != 0) {
            for (uint256 i = 0; i < holders.length; i++) {
                token.transfer(holders[i], balance / holders.length);
            }
        }
    }

    function withdrawAll() external onlyOwner {
        token.transfer(msg.sender, token.balanceOf(address(this)));
    }
}
