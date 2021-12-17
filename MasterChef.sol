// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import "./SwiftToken.sol";
import "./libs/IReferral.sol";

// MasterChef is the master of Swift. He can make Swift and he is a fair guy.
//
// Note that it's ownable and the owner wields tremendous power. The ownership
// will be transferred to a governance smart contract once Swift is sufficiently
// distributed and the community can show to govern itself.
//
// Have fun reading it. Hopefully it's bug-free. God bless.
contract MasterChef is Ownable, ReentrancyGuard {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    // Info of each user.
    struct UserInfo {
        uint256 amount; // How many LP tokens the user has provided.
        uint256 rewardDebt; // Reward debt. See explanation below.
        uint256 nextHarvestUntil; // When can the user harvest again in seconds
        //
        // We do some fancy math here. Basically, any point in time, the amount of FISHes
        // entitled to a user but is pending to be distributed is:
        //
        //   pending reward = (user.amount * pool.accSwiftPerShare) - user.rewardDebt
        //
        // Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:
        //   1. The pool's `accSwiftPerShare` (and `lastRewardBlock`) gets updated.
        //   2. User receives the pending reward sent to his/her address.
        //   3. User's `amount` gets updated.
        //   4. User's `rewardDebt` gets updated.
    }

    // Info of each pool.
    struct PoolInfo {
        IERC20 lpToken; // Address of LP token contract.
        uint256 allocPoint; // How many allocation points assigned to this pool. FISHes to distribute per block.
        uint256 lastRewardBlock; // Last block number that FISHes distribution occurs.
        uint256 accSwiftPerShare; // Accumulated FISHes per share, times 1e18. See below.
        uint16 depositFeeBP; // Deposit fee in basis points
        uint256 harvestInterval;  // Harvest interval in seconds
    }

    // The SWIFT TOKEN!
    SwiftToken public swiftToken;
    address public devAddress;
    address public feeAddress;

    // SWIFT tokens created per block.
    uint256 public swiftPerBlock = 0.05 ether;

    // Info of each pool.
    PoolInfo[] public poolInfo;
    // Info of each user that stakes LP tokens.
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    // Total allocation points. Must be the sum of all allocation points in all pools.
    uint256 public totalAllocPoint = 0;
    // The block number when SWIFT mining starts.
    uint256 public startBlock;

    // Swift referral contract address.
    IReferral public referral;
    // Referral commission rate in basis points. (2%)
    uint16 public referralCommissionRate = 200;
    // Max referral commission rate: 10%.
    uint16 public constant MAXIMUM_REFERRAL_COMMISSION_RATE = 1000;
    uint256 public constant MAXIMUM_HARVEST_INTERVAL = 14 days;

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(
        address indexed user,
        uint256 indexed pid,
        uint256 amount
    );
    event SetFeeAddress(address indexed user, address indexed newAddress);
    event SetDevAddress(address indexed user, address indexed newAddress);
    event SetVaultAddress(address indexed user, address indexed newAddress);
    event SetReferralAddress(
        address indexed user,
        IReferral indexed newAddress
    );
    event UpdateEmissionRate(address indexed user, uint256 swiftPerBlock);
    event ReferralCommissionPaid(
        address indexed user,
        address indexed referrer,
        uint256 commissionAmount
    );

    constructor(
        SwiftToken _swiftToken,
        uint256 _startBlock,
        address _devAddress,
        address _feeAddress
    ) public {
        swiftToken = _swiftToken;
        startBlock = _startBlock;

        devAddress = _devAddress;
        feeAddress = _feeAddress;
    }

    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    mapping(IERC20 => bool) public poolExistence;
    modifier nonDuplicated(IERC20 _lpToken) {
        require(poolExistence[_lpToken] == false, "nonDuplicated: duplicated");
        _;
    }

    // Add a new lp to the pool. Can only be called by the owner.
    function add(
        uint256 _allocPoint,
        IERC20 _lpToken,
        uint16 _depositFeeBP,
        uint256 _harvestInterval
    ) external onlyOwner nonDuplicated(_lpToken) {
        require(_depositFeeBP <= 400, "add: invalid deposit fee basis points");
        require(_harvestInterval <= MAXIMUM_HARVEST_INTERVAL, "add: invalid harvest interval");

        uint256 lastRewardBlock = block.number > startBlock
            ? block.number
            : startBlock;
        totalAllocPoint = totalAllocPoint.add(_allocPoint);
        poolExistence[_lpToken] = true;
        poolInfo.push(
            PoolInfo({
                lpToken: _lpToken,
                allocPoint: _allocPoint,
                lastRewardBlock: lastRewardBlock,
                accSwiftPerShare: 0,
                depositFeeBP: _depositFeeBP,
                harvestInterval: _harvestInterval
            })
        );
    }

    // Update the given pool's SWIFT allocation point and deposit fee. Can only be called by the owner.
    function set(
        uint256 _pid,
        uint256 _allocPoint,
        uint16 _depositFeeBP,
        uint256 _harvestInterval
    ) external onlyOwner {
        require(_depositFeeBP <= 400, "set: invalid deposit fee basis points");
        require(_harvestInterval <= MAXIMUM_HARVEST_INTERVAL, "set: invalid harvest interval");

        updatePool(_pid);

        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(
            _allocPoint
        );
        poolInfo[_pid].allocPoint = _allocPoint;
        poolInfo[_pid].depositFeeBP = _depositFeeBP;
        poolInfo[_pid].harvestInterval = _harvestInterval;
    }

    // Return reward multiplier over the given _from to _to block.
    function getMultiplier(uint256 _from, uint256 _to)
        public
        pure
        returns (uint256)
    {
        return _to.sub(_from);
    }

    // View function to see pending FISHes on frontend.
    function pendingSwift(uint256 _pid, address _user)
        external
        view
        returns (uint256)
    {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accSwiftPerShare = pool.accSwiftPerShare;
        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if (block.number > pool.lastRewardBlock && lpSupply != 0) {
            uint256 multiplier = getMultiplier(
                pool.lastRewardBlock,
                block.number
            );
            uint256 swiftReward = multiplier
                .mul(swiftPerBlock)
                .mul(pool.allocPoint)
                .div(totalAllocPoint);
            accSwiftPerShare = accSwiftPerShare.add(
                swiftReward.mul(1e18).div(lpSupply)
            );
        }
        return user.amount.mul(accSwiftPerShare).div(1e18).sub(user.rewardDebt);
    }

    // Update reward variables for all pools. Be careful of gas spending!
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    // Update reward variables of the given pool to be up-to-date.
    function updatePool(uint256 _pid) public {
        PoolInfo storage pool = poolInfo[_pid];
        if (block.number <= pool.lastRewardBlock) {
            return;
        }

        if(swiftToken.owner() != address(this)) {
            pool.lastRewardBlock = block.number;
            return;
        }

        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if (lpSupply == 0 || pool.allocPoint == 0) {
            pool.lastRewardBlock = block.number;
            return;
        }

        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
        uint256 swiftReward = multiplier
            .mul(swiftPerBlock)
            .mul(pool.allocPoint)
            .div(totalAllocPoint);

        uint256 devReward = swiftReward.div(10);
        swiftToken.mint(devAddress, devReward);
        swiftToken.mint(address(this), swiftReward);
        pool.accSwiftPerShare = pool.accSwiftPerShare.add(
            swiftReward.mul(1e18).div(lpSupply)
        );
        pool.lastRewardBlock = block.number;
    }

    // View function to see if user can fully harvest SWIFT.
    function canHarvest(uint256 _pid, address _user) public view returns (bool) {
        UserInfo storage user = userInfo[_pid][_user];
        return block.timestamp >= user.nextHarvestUntil;
    }

    // Pay or lockup pending SWIFT.
    function payOrBurnPendingSwift(uint256 _pid) internal {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];

        if (user.nextHarvestUntil == 0) {
            user.nextHarvestUntil = block.timestamp.add(pool.harvestInterval);
        }

        uint256 pending = user.amount.mul(pool.accSwiftPerShare).div(1e18).sub(user.rewardDebt);
        if (canHarvest(_pid, msg.sender)) {
            if (pending > 0) {
                uint256 devReward = pending.div(10);

                // reset lockup
                user.nextHarvestUntil = block.timestamp.add(pool.harvestInterval);

                // send rewards
                safeSwiftTransfer(msg.sender, pending.sub(devReward));
                payReferralCommission(msg.sender, pending.sub(devReward));
            }
        } else if (pending > 0) {
            // User gets 50% of rewards
            pending = pending.div(2);
            uint256 devReward = pending.div(10);
            pending = pending.sub(devReward);

            // send rewards
            safeSwiftTransfer(msg.sender, pending);
            payReferralCommission(msg.sender, pending);
            safeSwiftTransfer(0x000000000000000000000000000000000000dEaD, pending);
        }
    }

    // Deposit LP tokens to MasterChef for SWIFT allocation.
    function deposit(
        uint256 _pid,
        uint256 _amount,
        address _referrer
    ) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        updatePool(_pid);
        if (
            _amount > 0 &&
            address(referral) != address(0) &&
            _referrer != address(0) &&
            _referrer != msg.sender
        ) {
            referral.recordReferral(msg.sender, _referrer);
        }
        payOrBurnPendingSwift(_pid);
        if (_amount > 0) {
            pool.lpToken.safeTransferFrom(
                address(msg.sender),
                address(this),
                _amount
            );
            if (pool.depositFeeBP > 0) {
                uint256 depositFee = _amount.mul(pool.depositFeeBP).div(10000);
                pool.lpToken.safeTransfer(feeAddress, depositFee);
                user.amount = user.amount.add(_amount).sub(depositFee);
            } else {
                user.amount = user.amount.add(_amount);
            }
        }
        user.rewardDebt = user.amount.mul(pool.accSwiftPerShare).div(1e18);
        emit Deposit(msg.sender, _pid, _amount);
    }

    // Withdraw LP tokens from MasterChef.
    function withdraw(uint256 _pid, uint256 _amount) public nonReentrant {
        _withdraw(_pid, msg.sender, _amount);
    }

    function _withdraw(
        uint256 _pid,
        address _user,
        uint256 _amount
    ) internal {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];

        require(user.amount >= _amount, "withdraw: not good");
        updatePool(_pid);
        payOrBurnPendingSwift(_pid);
        if (_amount > 0) {
            user.amount = user.amount.sub(_amount);
            pool.lpToken.safeTransfer(address(_user), _amount);
        }
        user.rewardDebt = user.amount.mul(pool.accSwiftPerShare).div(1e18);
        emit Withdraw(_user, _pid, _amount);
    }

    // Withdraw without caring about rewards. EMERGENCY ONLY.
    function emergencyWithdraw(uint256 _pid) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        uint256 amount = user.amount;
        user.amount = 0;
        user.rewardDebt = 0;
        pool.lpToken.safeTransfer(address(msg.sender), amount);
        emit EmergencyWithdraw(msg.sender, _pid, amount);
    }

    // Safe swiftToken transfer function, just in case if rounding error causes pool to not have enough SWIFT.
    function safeSwiftTransfer(address _to, uint256 _amount) internal {
        uint256 swiftBal = swiftToken.balanceOf(address(this));
        bool transferSuccess = false;
        if (_amount > swiftBal) {
            transferSuccess = swiftToken.transfer(_to, swiftBal);
        } else {
            transferSuccess = swiftToken.transfer(_to, _amount);
        }
        require(transferSuccess, "safeSwiftTransfer: Transfer failed");
    }

    // Update dev address by the previous dev.
    function setDevAddress(address _devAddress) external onlyOwner {
        devAddress = _devAddress;
        emit SetDevAddress(msg.sender, _devAddress);
    }

    function setFeeAddress(address _feeAddress) external onlyOwner {
        feeAddress = _feeAddress;
        emit SetFeeAddress(msg.sender, _feeAddress);
    }

    function updateEmissionRate(uint256 _swiftTokenPerBlock)
        external
        onlyOwner
    {
        massUpdatePools();
        swiftPerBlock = _swiftTokenPerBlock;
        emit UpdateEmissionRate(msg.sender, _swiftTokenPerBlock);
    }

    // Update the referral contract address by the owner
    function setReferralAddress(IReferral _referral) external onlyOwner {
        referral = _referral;
        emit SetReferralAddress(msg.sender, _referral);
    }

    // Update referral commission rate by the owner
    function setReferralCommissionRate(uint16 _referralCommissionRate)
        external
        onlyOwner
    {
        require(
            _referralCommissionRate <= MAXIMUM_REFERRAL_COMMISSION_RATE,
            "setReferralCommissionRate: invalid referral commission rate basis points"
        );
        referralCommissionRate = _referralCommissionRate;
    }

    // Pay referral commission to the referrer who referred this user.
    function payReferralCommission(address _user, uint256 _pending) internal {
        if(swiftToken.owner() != address(this)) {
            return;
        }

        if (address(referral) != address(0) && referralCommissionRate > 0) {
            address referrer = referral.getReferrer(_user);
            uint256 commissionAmount = _pending.mul(referralCommissionRate).div(
                10000
            );

            if (referrer != address(0) && commissionAmount > 0) {
                swiftToken.mint(referrer, commissionAmount);
                emit ReferralCommissionPaid(_user, referrer, commissionAmount);
            }
        }
    }

    // Only update before start of farm
    function updateStartBlock(uint256 _startBlock) external onlyOwner {
        require(startBlock > block.number, "Farm already started");
        startBlock = _startBlock;

        for(uint256 i = 0; i < poolInfo.length; i++) {
            poolInfo[i].lastRewardBlock = _startBlock;
        }
    }

    // Switches active pool
    function switchActivePool(
        uint16[] calldata _activePids,
        uint16[] calldata _newPids,
        uint256[] calldata _newAllocPoints
    ) external onlyOwner {
        for (uint256 i = 0; i < _activePids.length; i++) {
            updatePool(_activePids[i]);
            PoolInfo storage activePool = poolInfo[_activePids[i]];
            activePool.allocPoint = 0;
        }

        for (uint256 i = 0; i < _newPids.length; i++) {
            PoolInfo storage newPool = poolInfo[_newPids[i]];
            newPool.allocPoint = _newAllocPoints[i];
        }
    }

    // Forces user to withdraw when allocpoint is set to 0
    function forceWithdraw(uint16 _pid, address[] memory _userAddresses)
        external
        onlyOwner
    {
        require(poolInfo[_pid].allocPoint == 0, "Alloc point is not 0");

        for (uint256 i = 0; i < _userAddresses.length; i++) {
            _withdraw(
                _pid,
                _userAddresses[i],
                userInfo[_pid][_userAddresses[i]].amount
            );
        }
    }

    // In the event we want to upgrade masterChef
    function transferSwiftTokenOwnership(address _newOwner)
        external
        onlyOwner
    {
        swiftToken.transferOwnership(_newOwner);
    }
}
