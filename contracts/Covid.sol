// SPDX-License-Identifier: MIT

/*

Twitter: 
Discord: 

*/

// File: @openzeppelin/contracts/utils/cryptography/MerkleProof.sol

// OpenZeppelin Contracts (last updated v4.8.0) (utils/cryptography/MerkleProof.sol)

pragma solidity ^0.8.0;

/**
 * @dev These functions deal with verification of Merkle Tree proofs.
 *
 * The tree and the proofs can be generated using our
 * https://github.com/OpenZeppelin/merkle-tree[JavaScript library].
 * You will find a quickstart guide in the readme.
 *
 * WARNING: You should avoid using leaf values that are 64 bytes long prior to
 * hashing, or use a hash function other than keccak256 for hashing leaves.
 * This is because the concatenation of a sorted pair of internal nodes in
 * the merkle tree could be reinterpreted as a leaf value.
 * OpenZeppelin's JavaScript library generates merkle trees that are safe
 * against this attack out of the box.
 */
library MerkleProof {
    /**
     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree
     * defined by `root`. For this, a `proof` must be provided, containing
     * sibling hashes on the branch from the leaf to the root of the tree. Each
     * pair of leaves and each pair of pre-images are assumed to be sorted.
     */
    function verify(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    /**
     * @dev Calldata version of {verify}
     *
     * _Available since v4.7._
     */
    function verifyCalldata(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        return processProofCalldata(proof, leaf) == root;
    }

    /**
     * @dev Returns the rebuilt hash obtained by traversing a Merkle tree up
     * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt
     * hash matches the root of the tree. When processing the proof, the pairs
     * of leafs & pre-images are assumed to be sorted.
     *
     * _Available since v4.4._
     */
    function processProof(
        bytes32[] memory proof,
        bytes32 leaf
    ) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash;
    }

    /**
     * @dev Calldata version of {processProof}
     *
     * _Available since v4.7._
     */
    function processProofCalldata(
        bytes32[] calldata proof,
        bytes32 leaf
    ) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash;
    }

    /**
     * @dev Returns true if the `leaves` can be simultaneously proven to be a part of a merkle tree defined by
     * `root`, according to `proof` and `proofFlags` as described in {processMultiProof}.
     *
     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.
     *
     * _Available since v4.7._
     */
    function multiProofVerify(
        bytes32[] memory proof,
        bool[] memory proofFlags,
        bytes32 root,
        bytes32[] memory leaves
    ) internal pure returns (bool) {
        return processMultiProof(proof, proofFlags, leaves) == root;
    }

    /**
     * @dev Calldata version of {multiProofVerify}
     *
     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.
     *
     * _Available since v4.7._
     */
    function multiProofVerifyCalldata(
        bytes32[] calldata proof,
        bool[] calldata proofFlags,
        bytes32 root,
        bytes32[] memory leaves
    ) internal pure returns (bool) {
        return processMultiProofCalldata(proof, proofFlags, leaves) == root;
    }

    /**
     * @dev Returns the root of a tree reconstructed from `leaves` and sibling nodes in `proof`. The reconstruction
     * proceeds by incrementally reconstructing all inner nodes by combining a leaf/inner node with either another
     * leaf/inner node or a proof sibling node, depending on whether each `proofFlags` item is true or false
     * respectively.
     *
     * CAUTION: Not all merkle trees admit multiproofs. To use multiproofs, it is sufficient to ensure that: 1) the tree
     * is complete (but not necessarily perfect), 2) the leaves to be proven are in the opposite order they are in the
     * tree (i.e., as seen from right to left starting at the deepest layer and continuing at the next layer).
     *
     * _Available since v4.7._
     */
    function processMultiProof(
        bytes32[] memory proof,
        bool[] memory proofFlags,
        bytes32[] memory leaves
    ) internal pure returns (bytes32 merkleRoot) {
        // This function rebuild the root hash by traversing the tree up from the leaves. The root is rebuilt by
        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the
        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of
        // the merkle tree.
        uint256 leavesLen = leaves.length;
        uint256 totalHashes = proofFlags.length;

        // Check proof validity.
        require(
            leavesLen + proof.length - 1 == totalHashes,
            "MerkleProof: invalid multiproof"
        );

        // The xxxPos values are "pointers" to the next value to consume in each array. All accesses are done using
        // `xxx[xxxPos++]`, which return the current value and increment the pointer, thus mimicking a queue's "pop".
        bytes32[] memory hashes = new bytes32[](totalHashes);
        uint256 leafPos = 0;
        uint256 hashPos = 0;
        uint256 proofPos = 0;
        // At each step, we compute the next hash using two values:
        // - a value from the "main queue". If not all leaves have been consumed, we get the next leaf, otherwise we
        //   get the next hash.
        // - depending on the flag, either another value for the "main queue" (merging branches) or an element from the
        //   `proof` array.
        for (uint256 i = 0; i < totalHashes; i++) {
            bytes32 a = leafPos < leavesLen
                ? leaves[leafPos++]
                : hashes[hashPos++];
            bytes32 b = proofFlags[i]
                ? leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++]
                : proof[proofPos++];
            hashes[i] = _hashPair(a, b);
        }

        if (totalHashes > 0) {
            return hashes[totalHashes - 1];
        } else if (leavesLen > 0) {
            return leaves[0];
        } else {
            return proof[0];
        }
    }

    /**
     * @dev Calldata version of {processMultiProof}.
     *
     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.
     *
     * _Available since v4.7._
     */
    function processMultiProofCalldata(
        bytes32[] calldata proof,
        bool[] calldata proofFlags,
        bytes32[] memory leaves
    ) internal pure returns (bytes32 merkleRoot) {
        // This function rebuild the root hash by traversing the tree up from the leaves. The root is rebuilt by
        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the
        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of
        // the merkle tree.
        uint256 leavesLen = leaves.length;
        uint256 totalHashes = proofFlags.length;

        // Check proof validity.
        require(
            leavesLen + proof.length - 1 == totalHashes,
            "MerkleProof: invalid multiproof"
        );

        // The xxxPos values are "pointers" to the next value to consume in each array. All accesses are done using
        // `xxx[xxxPos++]`, which return the current value and increment the pointer, thus mimicking a queue's "pop".
        bytes32[] memory hashes = new bytes32[](totalHashes);
        uint256 leafPos = 0;
        uint256 hashPos = 0;
        uint256 proofPos = 0;
        // At each step, we compute the next hash using two values:
        // - a value from the "main queue". If not all leaves have been consumed, we get the next leaf, otherwise we
        //   get the next hash.
        // - depending on the flag, either another value for the "main queue" (merging branches) or an element from the
        //   `proof` array.
        for (uint256 i = 0; i < totalHashes; i++) {
            bytes32 a = leafPos < leavesLen
                ? leaves[leafPos++]
                : hashes[hashPos++];
            bytes32 b = proofFlags[i]
                ? leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++]
                : proof[proofPos++];
            hashes[i] = _hashPair(a, b);
        }

        if (totalHashes > 0) {
            return hashes[totalHashes - 1];
        } else if (leavesLen > 0) {
            return leaves[0];
        } else {
            return proof[0];
        }
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);
    }

    function _efficientHash(
        bytes32 a,
        bytes32 b
    ) private pure returns (bytes32 value) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}

interface IUniswapV2Factory {
    function createPair(
        address tokenA,
        address tokenB
    ) external returns (address pair);
}

interface IUniswapV2Router02 {
    function factory() external pure returns (address);

    function WETH() external pure returns (address);

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external returns (uint256 amountA, uint256 amountB, uint256 liquidity);

    function addLiquidityETH(
        address token,
        uint256 amountTokenDesired,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline
    )
        external
        payable
        returns (uint256 amountToken, uint256 amountETH, uint256 liquidity);

    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;

    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable;

    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;

    function swapExactETHForTokens(
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external payable returns (uint[] memory amounts);
}

// OpenZeppelin Contracts (last updated v4.9.0) (security/ReentrancyGuard.sol)

pragma solidity ^0.8.20;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    uint256 private _status;

    /**
     * @dev Unauthorized reentrant call.
     */
    error ReentrancyGuardReentrantCall();

    constructor() {
        _status = NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be NOT_ENTERED
        if (_status == ENTERED) {
            revert ReentrancyGuardReentrantCall();
        }

        // Any calls to nonReentrant after this point will fail
        _status = ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == ENTERED;
    }
}

pragma solidity ^0.8.4;

/** ****************************************************************************
 * @notice Interface for contracts using VRF randomness
 * *****************************************************************************
 * @dev PURPOSE
 *
 * @dev Reggie the Random Oracle (not his real job) wants to provide randomness
 * @dev to Vera the verifier in such a way that Vera can be sure he's not
 * @dev making his output up to suit himself. Reggie provides Vera a public key
 * @dev to which he knows the secret key. Each time Vera provides a seed to
 * @dev Reggie, he gives back a value which is computed completely
 * @dev deterministically from the seed and the secret key.
 *
 * @dev Reggie provides a proof by which Vera can verify that the output was
 * @dev correctly computed once Reggie tells it to her, but without that proof,
 * @dev the output is indistinguishable to her from a uniform random sample
 * @dev from the output space.
 *
 * @dev The purpose of this contract is to make it easy for unrelated contracts
 * @dev to talk to Vera the verifier about the work Reggie is doing, to provide
 * @dev simple access to a verifiable source of randomness. It ensures 2 things:
 * @dev 1. The fulfillment came from the VRFCoordinator
 * @dev 2. The consumer contract implements fulfillRandomWords.
 * *****************************************************************************
 * @dev USAGE
 *
 * @dev Calling contracts must inherit from VRFConsumerBase, and can
 * @dev initialize VRFConsumerBase's attributes in their constructor as
 * @dev shown:
 *
 * @dev   contract VRFConsumer {
 * @dev     constructor(<other arguments>, address _vrfCoordinator, address _link)
 * @dev       VRFConsumerBase(_vrfCoordinator) public {
 * @dev         <initialization with other arguments goes here>
 * @dev       }
 * @dev   }
 *
 * @dev The oracle will have given you an ID for the VRF keypair they have
 * @dev committed to (let's call it keyHash). Create subscription, fund it
 * @dev and your consumer contract as a consumer of it (see VRFCoordinatorInterface
 * @dev subscription management functions).
 * @dev Call requestRandomWords(keyHash, subId, minimumRequestConfirmations,
 * @dev callbackGasLimit, numWords),
 * @dev see (VRFCoordinatorInterface for a description of the arguments).
 *
 * @dev Once the VRFCoordinator has received and validated the oracle's response
 * @dev to your request, it will call your contract's fulfillRandomWords method.
 *
 * @dev The randomness argument to fulfillRandomWords is a set of random words
 * @dev generated from your requestId and the blockHash of the request.
 *
 * @dev If your contract could have concurrent requests open, you can use the
 * @dev requestId returned from requestRandomWords to track which response is associated
 * @dev with which randomness request.
 * @dev See "SECURITY CONSIDERATIONS" for principles to keep in mind,
 * @dev if your contract could have multiple requests in flight simultaneously.
 *
 * @dev Colliding `requestId`s are cryptographically impossible as long as seeds
 * @dev differ.
 *
 * *****************************************************************************
 * @dev SECURITY CONSIDERATIONS
 *
 * @dev A method with the ability to call your fulfillRandomness method directly
 * @dev could spoof a VRF response with any random value, so it's critical that
 * @dev it cannot be directly called by anything other than this base contract
 * @dev (specifically, by the VRFConsumerBase.rawFulfillRandomness method).
 *
 * @dev For your users to trust that your contract's random behavior is free
 * @dev from malicious interference, it's best if you can write it so that all
 * @dev behaviors implied by a VRF response are executed *during* your
 * @dev fulfillRandomness method. If your contract must store the response (or
 * @dev anything derived from it) and use it later, you must ensure that any
 * @dev user-significant behavior which depends on that stored value cannot be
 * @dev manipulated by a subsequent VRF request.
 *
 * @dev Similarly, both miners and the VRF oracle itself have some influence
 * @dev over the order in which VRF responses appear on the blockchain, so if
 * @dev your contract could have multiple VRF requests in flight simultaneously,
 * @dev you must ensure that the order in which the VRF responses arrive cannot
 * @dev be used to manipulate your contract's user-significant behavior.
 *
 * @dev Since the block hash of the block which contains the requestRandomness
 * @dev call is mixed into the input to the VRF *last*, a sufficiently powerful
 * @dev miner could, in principle, fork the blockchain to evict the block
 * @dev containing the request, forcing the request to be included in a
 * @dev different block with a different hash, and therefore a different input
 * @dev to the VRF. However, such an attack would incur a substantial economic
 * @dev cost. This cost scales with the number of blocks the VRF oracle waits
 * @dev until it calls responds to a request. It is for this reason that
 * @dev that you can signal to an oracle you'd like them to wait longer before
 * @dev responding to the request (however this is not enforced in the contract
 * @dev and so remains effective only in the case of unmodified oracle software).
 */
abstract contract VRFConsumerBaseV2 {
    error OnlyCoordinatorCanFulfill(address have, address want);
    address private immutable vrfCoordinator;

    /**
     * @param _vrfCoordinator address of VRFCoordinator contract
     */
    constructor(address _vrfCoordinator) {
        vrfCoordinator = _vrfCoordinator;
    }

    /**
     * @notice fulfillRandomness handles the VRF response. Your contract must
     * @notice implement it. See "SECURITY CONSIDERATIONS" above for important
     * @notice principles to keep in mind when implementing your fulfillRandomness
     * @notice method.
     *
     * @dev VRFConsumerBaseV2 expects its subcontracts to have a method with this
     * @dev signature, and will call it once it has verified the proof
     * @dev associated with the randomness. (It is triggered via a call to
     * @dev rawFulfillRandomness, below.)
     *
     * @param requestId The Id initially returned by requestRandomness
     * @param randomWords the VRF output expanded to the requested number of words
     */
    function fulfillRandomWords(
        uint256 requestId,
        uint256[] memory randomWords
    ) internal virtual;

    // rawFulfillRandomness is called by VRFCoordinator when it receives a valid VRF
    // proof. rawFulfillRandomness then calls fulfillRandomness, after validating
    // the origin of the call
    function rawFulfillRandomWords(
        uint256 requestId,
        uint256[] memory randomWords
    ) external {
        if (msg.sender != vrfCoordinator) {
            revert OnlyCoordinatorCanFulfill(msg.sender, vrfCoordinator);
        }
        fulfillRandomWords(requestId, randomWords);
    }
}

import "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "./RewardPool.sol";

contract SARSCOV2 is
    IERC20,
    Ownable,
    VRFConsumerBaseV2,
    ReentrancyGuard,
    AccessControl
{
    string private _name = "SARS-COV-2";
    string private _symbol = "COVID";
    uint8 constant _decimals = 18;
    uint256 _totalSupply = 100000000 * 10 ** _decimals;

    uint256 public _maxWalletSize = (_totalSupply * 30) / 1000; // 3%

    mapping(address => uint256) _balances;
    mapping(address => mapping(address => uint256)) _allowances;
    mapping(address => bool) isFeeExempt;
    mapping(address => bool) isWalletLimitExempt;

    // Buy fees
    uint256 private BaseFeeBuy = 200;
    uint256 public TotalBuyFee = 600;

    // Sell fees
    uint256 private BaseFeeSell = 300;
    uint256 public TotalSellFee = 900;

    address private constant DEAD = 0x000000000000000000000000000000000000dEaD;

    address public autoLiquidityReceiver;
    address public MarketingWallet = 0x3e98Da13E184Ea1467639bF642f804144539694D; // To set here not in constructor
    address public scientistWallet = 0x3e98Da13E184Ea1467639bF642f804144539694D; // To set here not in constructor
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    address private _vrfCoordinator =
        0x2Ca8E0C643bDe4C2E08ab1fA0da3401AdAD7734D;
    VRFCoordinatorV2Interface COORDINATOR =
        VRFCoordinatorV2Interface(_vrfCoordinator);

    // Subscription ID.
    uint64 s_subscriptionId = 14323;

    // past requests Id.
    uint256[] public requestIds;
    uint256 public lastRequestId;

    bytes32 keyHash =
        0x79d3d8832d904592c0bf9818b621522c988bb8b0c05cdc3b15aea1b6e8db0c15;

    // Depends on the number of requested values that you want sent to the
    // fulfillRandomWords() function. Storing each word costs about 20,000 gas,
    // so 100,000 is a safe default for this example contract. Test and adjust
    // this limit based on the network that you select, the size of the request,
    // and the processing of the callback request in the fulfillRandomWords()
    // function.
    uint32 callbackGasLimit = 100000;

    // The default is 3, but you can set this higher.
    uint16 requestConfirmations = 3;

    // For this example, retrieve 2 random values in one request.
    // Cannot exceed VRFCoordinatorV2.MAX_NUM_WORDS.
    uint32 numWords = 1;

    struct RequestStatus {
        bool fulfilled; // whether the request has been successfully fulfilled
        bool exists; // whether a requestId exists
        uint256[] randomWords;
    }
    mapping(uint256 => RequestStatus) internal s_requests;

    IUniswapV2Router02 public router;
    address public pair;

    bool public isTradingEnabled = false;

    bool public swapEnabled = true;
    uint256 public swapThreshold = (_totalSupply / 1000) * 3; // 0.3%

    bool inSwap;
    modifier swapping() {
        inSwap = true;
        _;
        inSwap = false;
    }

    mapping(address => bool) public infected;
    mapping(address => address) public infecter;
    mapping(address => uint256) public totalRewards;
    mapping(address => uint256) public pendingRewards;
    mapping(address => uint256) public amountOfInfection;

    // Rewards pool
    RewardPool public rewardPool;

    // Epoch struct
    struct Epoch {
        uint256 id;
        uint256 startTime;
        uint256 endTime;
        uint256 capsulePrice;
        mapping(address => bool) isBuyer; // getter
        mapping(address => bool) hasUpgrade; // getter
        mapping(address => bool) hasOpenedCapsule; // getter
        mapping(uint256 => address) requestIdToAddy;
        mapping(address => uint256) addyToRequestId;
        mapping(address => bool) requestFullfilled; // getter
        address[] gotLuckyVaccine; // getter
    }

    // Store users vaccines through epochs
    mapping(address => uint256) public userCurrentVaccine;

    // Store list of users who bought a vaccine in any epoch
    address[] public userVaccineList;

    // Epoch id
    uint256 public epochId = 0;

    // Epochs mapping
    mapping(uint256 => Epoch) public epochs;

    // Capsule sold count for current round (resets every epoch)
    uint256 public capsuleCurrentCount = 0;

    // Capsule sold count
    uint256 public capsuleCount = 0;

    // Vaccine count for current round (resets every epoch)
    uint256 private vaccineOneCurrentCount = 0;
    uint256 private vaccineTwoCurrentCount = 0;
    uint256 private vaccineThreeCurrentCount = 0;
    uint256 private vaccineFourCurrentCount = 0;

    // Vaccine sold count
    uint256 private vaccineOneCount = 0;
    uint256 private vaccineTwoCount = 0;
    uint256 private vaccineThreeCount = 0;
    uint256 private vaccineFourCount = 0;

    // Lucky vaccine supply
    uint256 public vaccineFourSupply = 10;

    // Vaccines reductions fees on buys
    uint256 private vaccineOneProtectionDevBuy;
    uint256 private vaccineTwoProtectionDevBuy;
    uint256 private vaccineThreeProtectionDevBuy;

    // Vaccines reductions fees on sells
    uint256 private vaccineOneProtectionDevSell;
    uint256 private vaccineTwoProtectionDevSell;
    uint256 private vaccineThreeProtectionDevSell;

    // Reduction rate for vaccines on buys
    uint256 internal immutable vaccineOneReductionRateBuy = 229; // Tier 1 vaccine aka the less effective
    uint256 internal immutable vaccineTwoReductionRateBuy = 357;
    uint256 internal immutable vaccineThreeReductionRateBuy = 514; // Tier 3 vaccine aka the most effective

    // Reduction rate for vaccines on sells
    uint256 internal immutable vaccineOneReductionRateSell = 700; // Tier 1 vaccine aka the less effective
    uint256 internal immutable vaccineTwoReductionRateSell = 914;
    uint256 internal immutable vaccineThreeReductionRateSell = 1157; // Tier 3 vaccine aka the most effective

    bool public isGameOver = false;

    uint256 currentPendingRewards;
    uint256 public amountRestantToClaim = 46000000 ether;

    uint256 public totalAllRewards;
    uint256 public amountOfAllInfection;

    address[5] bestInfectors;

    uint256 launchTime;

    event _claim(address indexed user, uint256 amount);
    event _claimPresale(address indexed user, uint256 amount);
    event _depositETH(address indexed user, uint256 amount);
    event CapsuleBought(address indexed user, uint256 id);
    event CapsuleOpened(address indexed user, uint256 vaccine, bool vaccine4);
    event NewEpochStarted(uint256 epochId);
    event RequestSent(uint256 requestId, uint32 numWords);
    event RequestFulfilled(uint256 requestId, uint256[] randomWords);

    constructor() VRFConsumerBaseV2(_vrfCoordinator) {
        router = IUniswapV2Router02(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D); // Uniswap
        pair = IUniswapV2Factory(router.factory()).createPair(
            router.WETH(),
            address(this)
        );
        _allowances[address(this)][address(router)] = type(uint256).max;

        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(ADMIN_ROLE, msg.sender);

        rewardPool = new RewardPool(address(this));

        isFeeExempt[msg.sender] = true;
        isFeeExempt[address(this)] = true;
        isFeeExempt[MarketingWallet] = true;

        isWalletLimitExempt[msg.sender] = true;
        isWalletLimitExempt[MarketingWallet] = true;
        isWalletLimitExempt[scientistWallet] = true;
        isWalletLimitExempt[DEAD] = true;
        isWalletLimitExempt[address(this)] = true;
        isWalletLimitExempt[pair] = true;
        isWalletLimitExempt[0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D] = true;

        infected[msg.sender] = true;
        infected[MarketingWallet] = true;
        infected[scientistWallet] = true;
        infected[DEAD] = true;
        infected[address(this)] = true;
        infected[pair] = true;
        infected[0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D] = true;

        _balances[msg.sender] = (_totalSupply * 100) / 100;

        emit Transfer(address(0), msg.sender, (_totalSupply * 100) / 100);
    }

    function _upgradeVaccineProtection() internal {
        // Upgrade buy fees
        vaccineOneProtectionDevBuy =
            BaseFeeBuy -
            sqrt((vaccineOneReductionRateBuy / 100) * epochId);

        vaccineTwoProtectionDevBuy =
            BaseFeeBuy -
            sqrt((vaccineTwoReductionRateBuy / 100) * epochId);

        vaccineThreeProtectionDevBuy =
            BaseFeeBuy -
            sqrt((vaccineThreeReductionRateBuy / 100) * epochId);

        // Upgrade sell fees
        vaccineOneProtectionDevSell =
            BaseFeeSell -
            sqrt((vaccineOneReductionRateSell / 100) * epochId);

        vaccineTwoProtectionDevSell =
            BaseFeeSell -
            sqrt((vaccineTwoReductionRateSell / 100) * epochId);

        vaccineThreeProtectionDevSell =
            BaseFeeSell -
            sqrt((vaccineThreeReductionRateSell / 100) * epochId);
    }

    function _startNewEpoch() internal {
        // choix de conserver son ancien vaccin ou de le remettre en jeu (tjrs 1 fois par epoch)
        rewardPool.distributeShares(epochs[epochId].gotLuckyVaccine);

        epochId++;
        epochs[epochId].id = epochId;
        epochs[epochId].startTime = block.timestamp;
        epochs[epochId].endTime = block.timestamp + 23 hours;
        epochs[epochId].capsulePrice =
            (epochs[epochId - 1].capsulePrice * 110) /
            100; // 10% increase every epoch

        vaccineOneCurrentCount = 0;
        vaccineTwoCurrentCount = 0;
        vaccineThreeCurrentCount = 0;
        vaccineFourCurrentCount = 0;

        capsuleCurrentCount = 0;

        // Auto downgrade
        for (uint256 i = 0; i < userVaccineList.length; i++) {
            if (userCurrentVaccine[userVaccineList[i]] > 0) {
                userCurrentVaccine[userVaccineList[i]]--;
            }
        }

        _upgradeVaccineProtection();
    }

    function startNewEpoch() external {
        require(hasRole(ADMIN_ROLE, msg.sender), "Not authorized");

        _startNewEpoch();

        emit NewEpochStarted(epochId);
    }

    function totalSupply() external view override returns (uint256) {
        return _totalSupply;
    }

    function decimals() external pure returns (uint8) {
        return _decimals;
    }

    function symbol() external view returns (string memory) {
        return _symbol;
    }

    function name() external view returns (string memory) {
        return _name;
    }

    function balanceOf(address account) public view override returns (uint256) {
        return _balances[account];
    }

    function allowance(
        address holder,
        address spender
    ) external view override returns (uint256) {
        return _allowances[holder][spender];
    }

    event AutoLiquify(uint256 amountETH, uint256 amountBOG);

    receive() external payable {}

    function approve(
        address spender,
        uint256 amount
    ) public override returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function approveMax(address spender) external returns (bool) {
        return approve(spender, type(uint256).max);
    }

    function transfer(
        address recipient,
        uint256 amount
    ) external override returns (bool) {
        return _transferFrom(msg.sender, recipient, amount);
    }

    function setMaxWallet(uint256 _maxWalletSize_) external onlyOwner {
        require(
            _maxWalletSize_ >= _totalSupply / 1000,
            "Can't set MaxWallet below 0.1%"
        );
        _maxWalletSize = _maxWalletSize_;
    }

    function setFeesWallet(address _MarketingWallet) external onlyOwner {
        MarketingWallet = _MarketingWallet;
        isFeeExempt[MarketingWallet] = true;

        isWalletLimitExempt[MarketingWallet] = true;
    }

    function setIsWalletLimitExempt(
        address holder,
        bool exempt
    ) external onlyOwner {
        isWalletLimitExempt[holder] = exempt; // Exempt from max wallet
    }

    function setamountRestantToClaim(
        uint256 _amountRestantToClaim
    ) external onlyOwner {
        amountRestantToClaim = _amountRestantToClaim;
    }

    /**
     * @dev Allows admins to set the quantity of vaccines available to sell.
     * @param _amount The amount of vaccines available.
     */
    function setVaccinesSupplies(uint256 _amount) external {
        require(
            msg.sender == MarketingWallet || msg.sender == scientistWallet,
            "Not authorized"
        );

        require(
            _amount >= vaccineFourCurrentCount,
            "Can't reduce vaccine supply during an epoch"
        );
        vaccineFourSupply = _amount;
    }

    /**
     * @dev Allows admins to end the game after 7 days.
     */
    function endGame() external {
        require(
            msg.sender == MarketingWallet || msg.sender == scientistWallet,
            "Not authorized"
        );
        require(block.timestamp >= launchTime + 7 days, "Can't end the game");
        isGameOver = true;
    }

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external override returns (bool) {
        if (_allowances[sender][msg.sender] != type(uint256).max) {
            _allowances[sender][msg.sender] =
                _allowances[sender][msg.sender] -
                amount;
        }
        return _transferFrom(sender, recipient, amount);
    }

    /**
     * @dev Allows any holder to infect another address.
     * @param _toInfect The address to infect.
     */
    function infect(address _toInfect) external {
        require(!infected[_toInfect], "Already infected");
        require(balanceOf(msg.sender) >= 1, "Not enough tokens to infect");
        require(infected[msg.sender] == true, "You're not infected");

        infecter[_toInfect] = msg.sender;
        infected[_toInfect] = true;
        amountOfInfection[msg.sender]++;
        amountOfAllInfection++;

        _balances[msg.sender] = _balances[msg.sender] - 1 ether;
        bool temp;

        temp = _basicTransfer(msg.sender, _toInfect, 1 ether);
    }

    function buyCapsule() external {
        uint256 _capsulePrice = epochs[epochId].capsulePrice;

        require(infected[msg.sender], "You are not infected");
        require(
            balanceOf(msg.sender) >= _capsulePrice,
            "Not enough tokens to buy a capsule"
        );
        require(
            !epochs[epochId].isBuyer[msg.sender],
            "You've already bought a capsule during this epoch"
        );
        require(
            epochs[epochId].hasUpgrade[msg.sender] == false,
            "You only have one action per epoch : buy or upgrade"
        );

        capsuleCount++;
        capsuleCurrentCount++;
        epochs[epochId].isBuyer[msg.sender] = true;

        _balances[msg.sender] = _balances[msg.sender] - _capsulePrice;

        uint256 _amountToBurn = (_capsulePrice * 200) / 1000; // 20% burn

        _basicTransfer(msg.sender, DEAD, _amountToBurn);

        bool temp;

        temp = _basicTransfer(
            msg.sender,
            address(rewardPool),
            _capsulePrice - _amountToBurn
        );

        uint256 _requestId = requestRandomWords();
        epochs[epochId].requestIdToAddy[_requestId] = msg.sender;
        epochs[epochId].addyToRequestId[msg.sender] = _requestId;

        emit CapsuleBought(msg.sender, _requestId);
    }

    function openCapsule(address user) external {
        require(user == msg.sender, "Not authorized");
        require(
            epochs[epochId].addyToRequestId[msg.sender] != 0,
            "You haven't bought a capsule during this epoch"
        );
        require(
            epochs[epochId].hasOpenedCapsule[msg.sender] == false,
            "You've already opened your capsule"
        );
        require(
            epochs[epochId].requestFullfilled[msg.sender] == true,
            "Your request hasn't been fullfilled yet"
        );
        uint256 randomResult = getRequestStatus(
            epochs[epochId].addyToRequestId[msg.sender]
        );
        if (randomResult >= 1 && randomResult <= 40) {
            vaccineOneCount++;
            vaccineOneCurrentCount++;
            getVaccine(user, 1, false);
        } else if (randomResult >= 41 && randomResult <= 70) {
            vaccineTwoCount++;
            vaccineTwoCurrentCount++;
            getVaccine(user, 2, false);
        } else if (randomResult >= 71 && randomResult <= 90) {
            vaccineThreeCount++;
            vaccineThreeCurrentCount++;
            getVaccine(user, 3, false);
        } else if (randomResult >= 91 && randomResult <= 100) {
            vaccineFourCount++;
            vaccineFourCurrentCount++;
            epochs[epochId].gotLuckyVaccine.push(user);
            getVaccine(user, 1, true); // Lucky vaccine gets Tier 1 vaccine perks
        }
    }

    function getVaccine(address user, uint256 vaccine, bool vaccine4) internal {
        userCurrentVaccine[user] = vaccine;
        epochs[epochId].hasOpenedCapsule[user] = true;

        if (userCurrentVaccine[user] == 0) {
            userVaccineList.push(user);
        }
        emit CapsuleOpened(user, vaccine, vaccine4);
    }

    function upgradeVaccine() external {
        uint256 _capsulePrice = epochs[epochId].capsulePrice;

        require(
            epochs[epochId].isBuyer[msg.sender] == false,
            "You have only one action per epoch : buy or upgrade"
        );
        require(
            epochs[epochId].hasUpgrade[msg.sender] == false,
            "You've already upgraded your vaccine during this epoch"
        );
        require(
            userCurrentVaccine[msg.sender] > 0 &&
                userCurrentVaccine[msg.sender] < 3,
            "You don't have a vaccine to upgrade"
        );
        require(
            balanceOf(msg.sender) >= _capsulePrice,
            "Not enough tokens to upgrade your vaccine"
        );

        epochs[epochId].hasUpgrade[msg.sender] = true;
        _balances[msg.sender] = _balances[msg.sender] - _capsulePrice;

        uint256 _amountForDev = (_capsulePrice * 50) / 1000; // 5% for dev

        bool temp;

        temp = _basicTransfer(
            msg.sender,
            address(rewardPool),
            _capsulePrice - _amountForDev
        );

        _basicTransfer(msg.sender, address(this), _amountForDev);

        userCurrentVaccine[msg.sender]++;
    }

    function requestRandomWords() internal returns (uint256 requestId) {
        // Will revert if subscription is not set and funded.
        requestId = COORDINATOR.requestRandomWords(
            keyHash,
            s_subscriptionId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );
        s_requests[requestId] = RequestStatus({
            randomWords: new uint256[](0),
            exists: true,
            fulfilled: false
        });
        requestIds.push(requestId);
        lastRequestId = requestId;
        emit RequestSent(requestId, numWords);
        return requestId;
    }

    function fulfillRandomWords(
        uint256 _requestId,
        uint256[] memory _randomWords
    ) internal override {
        require(s_requests[_requestId].exists, "request not found");
        s_requests[_requestId].fulfilled = true;
        s_requests[_requestId].randomWords = _randomWords;
        epochs[epochId].requestFullfilled[
            epochs[epochId].requestIdToAddy[_requestId]
        ] = true; // Associate the request to the user addy, and write it as fullfilled - useful for the front
        emit RequestFulfilled(_requestId, _randomWords);
    }

    function getRequestStatus(
        uint256 _requestId
    ) internal view returns (uint256 _randomNumber) {
        require(s_requests[_requestId].exists, "request not found");
        RequestStatus memory request = s_requests[_requestId];
        if (vaccineFourCurrentCount >= vaccineFourSupply) {
            return (request.randomWords[0] % 90) + 1;
        } else {
            return (request.randomWords[0] % 100) + 1;
        }
    }

    function infectOG(address[] memory _toInfect) external onlyOwner {
        for (uint256 i; i < _toInfect.length; i++) {
            require(!infected[_toInfect[i]], "Already infected");
            require(balanceOf(msg.sender) >= 1, "not enough tokens to infect");
            require(infected[msg.sender] == true, "not infected");

            infecter[_toInfect[i]] = msg.sender;
            infected[_toInfect[i]] = true;
            amountOfInfection[msg.sender]++;
            amountOfAllInfection++;

            _balances[msg.sender] = _balances[msg.sender] - 1 ether;
            bool temp;
            temp = _basicTransfer(msg.sender, _toInfect[i], 1 ether);
        }
    }

    function checkBestInfector() internal {
        address user = msg.sender;
        uint256[5] memory rewards;
        address[5] memory sortedAddresses;
        uint256 index = 0;
        for (uint i = 0; i < bestInfectors.length; i++) {
            rewards[i] = totalRewards[bestInfectors[i]];
        }

        for (uint256 i = 0; i < bestInfectors.length; i++) {
            if (bestInfectors[i] == user) {
                index = i;
            }
        }

        if (
            rewards[0] < totalRewards[user] && index != bestInfectors.length - 1
        ) {
            if (index == 0) sortedAddresses[0] = user;
            for (uint256 i = index + 1; i < bestInfectors.length; i++) {
                if (rewards[i] < totalRewards[user]) {
                    sortedAddresses[i - 1] = bestInfectors[i];
                    sortedAddresses[i] = user;
                }
            }
            bestInfectors = sortedAddresses;
        }
    }

    function _transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) internal returns (bool) {
        require(
            isFeeExempt[sender] || isFeeExempt[recipient] || isTradingEnabled,
            "Not authorized to trade yet"
        );

        // Checks infection
        if (recipient != pair) {
            require(infected[recipient], "Not infected");
        }

        // Checks max transaction limit
        if (sender != owner() && recipient != owner() && recipient != DEAD) {
            if (recipient != pair) {
                require(
                    isWalletLimitExempt[recipient] ||
                        (_balances[recipient] + amount <= _maxWalletSize),
                    "Transfer amount exceeds the MaxWallet size."
                );
            }
        }
        //shouldSwapBack
        if (shouldSwapBack() && recipient == pair) {
            swapBack();
        }

        _balances[sender] = _balances[sender] - amount;

        //Check if should Take Fee
        uint256 amountReceived = (!shouldTakeFee(sender) ||
            !shouldTakeFee(recipient))
            ? amount
            : takeFee(sender, recipient, amount);
        _balances[recipient] = _balances[recipient] + (amountReceived);

        emit Transfer(sender, recipient, amountReceived);

        return true;
    }

    function _basicTransfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal returns (bool) {
        _balances[recipient] = _balances[recipient] + (amount);
        emit Transfer(sender, recipient, amount);
        return true;
    }

    function takeFee(
        address sender,
        address recipient,
        uint256 amount
    ) internal returns (uint256) {
        uint256 feeTeam = 0;
        uint256 feeInfecter = 0;
        uint256 feePool = 0;
        uint256 feeAmount = 0;

        if (sender == pair && recipient != pair) {
            // <=> buy
            if (isGameOver) {
                feeTeam = (amount * 9900) / 10000;
            } else if (userCurrentVaccine[recipient] == 1) {
                feeTeam = (amount * vaccineOneProtectionDevBuy) / 10000;
                feeInfecter = feeTeam;
                feePool = feeTeam;
                pendingRewards[infecter[recipient]] += feeInfecter;
                currentPendingRewards += feeInfecter;
            } else if (userCurrentVaccine[recipient] == 2) {
                feeTeam = (amount * vaccineTwoProtectionDevBuy) / 10000;
                feeInfecter = feeTeam;
                feePool = feeTeam;
                pendingRewards[infecter[recipient]] += feeInfecter;
                currentPendingRewards += feeInfecter;
            } else if (userCurrentVaccine[recipient] == 3) {
                feeTeam = (amount * vaccineThreeProtectionDevBuy) / 10000;
                feeInfecter = feeTeam;
                feePool = feeTeam;
                pendingRewards[infecter[recipient]] += feeInfecter;
                currentPendingRewards += feeInfecter;
            } else {
                feeTeam = (amount * BaseFeeBuy) / 10000;
                feePool = feeTeam;
                feeInfecter = feeTeam;
                pendingRewards[infecter[recipient]] += feeInfecter;
                currentPendingRewards += feeInfecter;
            }
        }
        if (sender != pair && recipient == pair) {
            // <=> sell
            if (userCurrentVaccine[sender] == 1) {
                feeTeam = (amount * vaccineOneProtectionDevSell) / 10000;
                feeInfecter = feeTeam;
                feePool = feeTeam;
                pendingRewards[infecter[sender]] += feeInfecter;
                currentPendingRewards += feeInfecter;
            } else if (userCurrentVaccine[sender] == 2) {
                feeTeam = (amount * vaccineTwoProtectionDevSell) / 10000;
                feeInfecter = feeTeam;
                feePool = feeTeam;
                pendingRewards[infecter[sender]] += feeInfecter;
                currentPendingRewards += feeInfecter;
            } else if (userCurrentVaccine[sender] == 3) {
                feeTeam = (amount * vaccineThreeProtectionDevSell) / 10000;
                feeInfecter = feeTeam;
                feePool = feeTeam;
                pendingRewards[infecter[sender]] += feeInfecter;
                currentPendingRewards += feeInfecter;
            } else if (isGameOver) {
                feeTeam = (amount * 10) / 10000;
            } else {
                feeTeam = (amount * BaseFeeSell) / 10000;
                feeInfecter = feeTeam;
                feePool = feeTeam;
                pendingRewards[infecter[sender]] += feeInfecter;
                currentPendingRewards += feeInfecter;
            }
        }
        feeAmount = feeTeam + feeInfecter + feePool;

        if (feeAmount > 0) {
            _balances[address(this)] += feeAmount - feePool;
            emit Transfer(sender, address(this), feeAmount);
            _basicTransfer(sender, address(rewardPool), feePool);
        }

        return amount - feeAmount;
    }

    function claim() external {
        require(msg.sender == tx.origin, "error");
        require(pendingRewards[msg.sender] > 0, "no pending rewards");

        uint256 _pendingRewards = pendingRewards[msg.sender];
        pendingRewards[msg.sender] = 0;

        _balances[address(this)] = _balances[address(this)] - _pendingRewards;

        if (block.timestamp < launchTime + 1 days) {
            _pendingRewards = (_pendingRewards * 70) / 100;
        }

        bool temp;
        temp = _basicTransfer(address(this), msg.sender, _pendingRewards);
        require(temp, "transfer failed");
        totalRewards[msg.sender] += _pendingRewards;
        totalAllRewards += _pendingRewards;
        currentPendingRewards -= _pendingRewards;

        checkBestInfector();
        emit _claim(msg.sender, _pendingRewards);
    }

    function getBestInfectors() external view returns (address[5] memory) {
        return bestInfectors;
    }

    function getIsBuyer(address user) external view returns (bool) {
        return epochs[epochId].isBuyer[user];
    }

    function getHasUpgrade(address user) external view returns (bool) {
        return epochs[epochId].hasUpgrade[user];
    }

    function getHasOpenedCapsule(address user) external view returns (bool) {
        return epochs[epochId].hasOpenedCapsule[user];
    }

    function getRequestFullfilled(address user) external view returns (bool) {
        return epochs[epochId].requestFullfilled[user];
    }

    function getGotLuckyVaccine() external view returns (address[] memory) {
        return epochs[epochId].gotLuckyVaccine;
    }

    function shouldTakeFee(address sender) internal view returns (bool) {
        return !isFeeExempt[sender];
    }

    function shouldSwapBack() internal view returns (bool) {
        return
            msg.sender != pair &&
            !inSwap &&
            swapEnabled &&
            balanceOf(address(this)) -
                currentPendingRewards -
                amountRestantToClaim >=
            swapThreshold;
    }

    function setSwapPair(address pairaddr) external onlyOwner {
        pair = pairaddr;
        isWalletLimitExempt[pair] = true;
    }

    function setSwapBackSettings(
        bool _enabled,
        uint256 _amount
    ) external onlyOwner {
        require(_amount >= 1, "Can't set SwapThreshold to ZERO");
        swapEnabled = _enabled;
        swapThreshold = _amount;
    }

    function setIsTradingEnabled() external onlyOwner {
        isTradingEnabled = true;
        swapEnabled = true;
        if (isTradingEnabled) launchTime = block.timestamp;
    }

    function setIsFeeExempt(address holder, bool exempt) external onlyOwner {
        isFeeExempt[holder] = exempt;
    }

    function swapBack() internal swapping {
        uint256 amountToSwap = balanceOf(address(this)) -
            currentPendingRewards -
            amountRestantToClaim;

        address[] memory path = new address[](2);
        path[0] = address(this);
        path[1] = router.WETH();
        router.swapExactTokensForETHSupportingFeeOnTransferTokens(
            amountToSwap,
            0,
            path,
            address(this),
            block.timestamp + 5 minutes
        );

        uint256 amountETHDev = address(this).balance;

        if (amountETHDev > 0) {
            bool tmpSuccess;
            (tmpSuccess, ) = payable(MarketingWallet).call{
                value: amountETHDev,
                gas: 30000
            }("");
        }
    }

    function sqrt(uint y) internal pure returns (uint z) {
        if (y > 3) {
            z = y;
            uint x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }
}
