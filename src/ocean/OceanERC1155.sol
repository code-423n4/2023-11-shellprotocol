// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.3.2 (token/ERC1155/ERC1155.sol)
// Cowri Labs, Inc., modifications licensed under: MIT

pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/IERC1155MetadataURI.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";

// OpenZeppelin Inherited Contracts
import { ReentrancyGuard } from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

// ShellV2 Interface
import { IOceanToken } from "./IOceanToken.sol";

// ShellV2 Permit Signature
import { ERC1155PermitSignatureExtension } from "./ERC1155PermitSignatureExtension.sol";

/**
 * @dev Implementation of the basic standard multi-token.
 * See https://eips.ethereum.org/EIPS/eip-1155
 * Originally based on code by Enjin: https://github.com/enjin/erc-1155
 *
 * _Available since v3.1._
 * @dev modifications include removing unused hooks, creating a minting
 *  function that does not do a safeTransferAcceptanceCheck, and adding a
 *  mapping and functions to register and manage authority over tokens.
 * @dev Registered Tokens are Ocean-native issuances, such as Liquidity
 *  Provider tokens issued by an AMM built on top of the Ocean.
 */
contract OceanERC1155 is
    Context,
    ERC165,
    ERC1155PermitSignatureExtension,
    IERC1155,
    IERC1155MetadataURI,
    IOceanToken,
    Ownable,
    ReentrancyGuard
{
    //*********************************************************************//
    // --------------------------- custom errors ------------------------- //
    //*********************************************************************//
    error FORWARDER_NOT_APPROVED();
    error INVALID_ERC721_AMOUNT();
    error NO_DECIMAL_METHOD();
    error NO_RECURSIVE_WRAPS();
    error NO_RECURSIVE_UNWRAPS();

    using Address for address;

    /// @notice Mapping from token ID to address with authority over token's issuance
    mapping(uint256 => address) public tokensToPrimitives;

    uint256 constant FUSE_INTACT = 1;
    uint256 constant FUSE_BROKEN = 0;
    uint256 public permitFuse;

    // Mapping from token ID to account balances
    mapping(uint256 => mapping(address => uint256)) private _balances;

    // Mapping from account to operator approvals
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    // Used as the URI for all token types by relying on ID substitution, e.g. https://token-cdn-domain/{id}.json
    string private _uri;

    event PermitFuseBroken(address indexed breakerAddress);
    event NewTokensRegistered(address indexed creator, uint256[] tokens, uint256[] nonces);

    /**
     * @dev See {_setURI}.
     */
    constructor(string memory uri_) ERC1155PermitSignatureExtension(bytes("shell-protocol-ocean"), bytes("1")) {
        _setURI(uri_);
        permitFuse = FUSE_INTACT;
    }

    function breakPermitFuse() external onlyOwner {
        permitFuse = FUSE_BROKEN;
        emit PermitFuseBroken(msg.sender);
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IERC1155).interfaceId || interfaceId == type(IERC1155MetadataURI).interfaceId
            || super.supportsInterface(interfaceId);
    }

    /**
     * @dev See {IERC1155MetadataURI-uri}.
     *
     * This implementation returns the same URI for *all* token types. It relies
     * on the token type ID substitution mechanism
     * https://eips.ethereum.org/EIPS/eip-1155#metadata[defined in the EIP].
     *
     * Clients calling this function must replace the `\{id\}` substring with the
     * actual token type ID.
     */
    function uri(uint256) public view virtual override returns (string memory) {
        return _uri;
    }

    /**
     * @dev See {IERC1155-balanceOf}.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     */
    function balanceOf(address account, uint256 id) public view virtual override returns (uint256) {
        require(account != address(0), "balanceOf(address(0))");
        return _balances[id][account];
    }

    /**
     * @dev See {IERC1155-balanceOfBatch}.
     *
     * Requirements:
     *
     * - `accounts` and `ids` must have the same length.
     */
    function balanceOfBatch(
        address[] memory accounts,
        uint256[] memory ids
    )
        public
        view
        virtual
        override
        returns (uint256[] memory)
    {
        require(accounts.length == ids.length, "accounts.length != ids.length");

        uint256[] memory batchBalances = new uint256[](accounts.length);

        for (uint256 i = 0; i < accounts.length; ++i) {
            batchBalances[i] = balanceOf(accounts[i], ids[i]);
        }

        return batchBalances;
    }

    /**
     * @dev See {IERC1155-setApprovalForAll}.
     */
    function setApprovalForAll(address operator, bool approved) public virtual override {
        _setApprovalForAll(_msgSender(), operator, approved);
    }

    /**
     * @dev See {IERC1155-isApprovedForAll}.
     */
    function isApprovedForAll(address account, address operator) public view virtual override returns (bool) {
        return _operatorApprovals[account][operator];
    }

    /**
     * @dev See {IERC1155-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    )
        public
        virtual
        override
        nonReentrant
    {
        require(from == _msgSender() || isApprovedForAll(from, _msgSender()), "not owner nor approved");
        _safeTransferFrom(from, to, id, amount, data);
    }

    /**
     * @dev See {IERC1155-safeBatchTransferFrom}.
     */
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    )
        public
        virtual
        override
        nonReentrant
    {
        require(from == _msgSender() || isApprovedForAll(from, _msgSender()), "not owner nor approved");
        _safeBatchTransferFrom(from, to, ids, amounts, data);
    }

    /**
     * @dev Registered Tokens are tokens issued directly on the ocean's 1155 ledger.
     * @dev These are tokens that cannot be wrapped or unwrapped.
     * @dev We don't validate the inputs.  The happy path usage is for callers
     *  to obtain authority over tokens that have their ids derived from
     *  successive nonces.
     *
     *  registerNewTokens(0, n):
     *      _calculateOceanId(caller, 0)
     *      _calculateOceanId(caller, 1)
     *      ...
     *      _calculateOceanId(caller, n)
     *
     *  Since the ocean tracks the one to one relationship of:
     *    token => authority
     *  but not the one to many relationship of:
     *    authority => tokens
     *  it is nice UX to be able to re-derive the tokens on the fly from the
     *  authority's address and successive (predictable) nonces are used.
     *
     *  However, if the caller wants to use this interface in a different way,
     *  they could easily make a call like:
     *  registerNewTokens($SOME_NUMBER, 1); to use $SOME_NUMBER
     *  as the nonce.  A user could request to buy an in-ocean nft with a
     *  specific seed value, and the external contract gains authority over
     *  this id on the fly in order to sell it.
     *
     *  If the caller tries to reassert authority over a token they've already
     *  registered, they just waste gas.  If a caller expects to create
     *  new tokens over time, it should track how many tokens it has already
     *  created
     * @dev the guiding philosophy is to track only essential information in
     *  the Ocean's state, and let users (both EOAs and contracts) track other
     *  information as they see fit.
     * @param currentNumberOfTokens the starting nonce
     * @param numberOfAdditionalTokens the number of new tokens registered
     * @return oceanIds Ocean IDs of the tokens the caller now has authority over
     */
    function registerNewTokens(
        uint256 currentNumberOfTokens,
        uint256 numberOfAdditionalTokens
    )
        external
        override
        returns (uint256[] memory oceanIds)
    {
        oceanIds = new uint256[](numberOfAdditionalTokens);
        uint256[] memory nonces = new uint256[](numberOfAdditionalTokens);

        for (uint256 i = 0; i < numberOfAdditionalTokens; ++i) {
            uint256 tokenNonce = currentNumberOfTokens + i;
            uint256 newToken = _calculateOceanId(msg.sender, tokenNonce);
            nonces[i] = tokenNonce;
            oceanIds[i] = newToken;
            tokensToPrimitives[newToken] = msg.sender;
        }
        emit NewTokensRegistered(msg.sender, oceanIds, nonces);
    }

    function _signaturesEnabled() internal view override returns (bool) {
        return bool(permitFuse == FUSE_INTACT);
    }

    /**
     * @dev returns true when a primitive did NOT register an ID
     *
     * Used  to determine if the Ocean needs to explicitly mint/burn tokens
     *  balance a transaction.
     */
    function _isNotTokenOfPrimitive(uint256 oceanId, address primitive) internal view returns (bool) {
        return (tokensToPrimitives[oceanId] != primitive);
    }

    /**
     * @dev calculates a collision-resistant token ID
     *
     * OceanIds are derived from their origin. The origin can be:
     *  - ERC20 contracts that have their token wrapped into the ocean
     *  - ERC721 contracts that have tokens with IDs wrapped into the ocean
     *  - ERC1155 contracts that have tokens with IDs wrapped into the ocean
     *  - Contracts that issue Ocean-native tokens
     *      When a contract registers a new token, the token has an associated
     *      nonce, which functions just like an ERC721 or ERC1155 token ID.
     *
     * The oceanId is calculated by using the contract address of the origin
     *      and the relevant ID.  For ERC20 tokens, the ID is always 0.
     */
    function _calculateOceanId(address tokenContract, uint256 tokenId) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(tokenContract, tokenId)));
    }

    /**
     * @dev Transfers `amount` tokens of token type `id` from `from` to `to`.
     *
     * Emits a {TransferSingle} event.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - `from` must have a balance of tokens of type `id` of at least `amount`.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155Received} and return the
     * acceptance magic value.
     */
    function _safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    )
        internal
        virtual
    {
        require(to != address(0), "transfer to the zero address");

        address operator = _msgSender();

        uint256 fromBalance = _balances[id][from];
        require(fromBalance >= amount, "insufficient balance");
        unchecked {
            _balances[id][from] = fromBalance - amount;
        }
        _balances[id][to] += amount;

        emit TransferSingle(operator, from, to, id, amount);

        _doSafeTransferAcceptanceCheck(operator, from, to, id, amount, data);
    }

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {_safeTransferFrom}.
     *
     * Emits a {TransferBatch} event.
     *
     * Requirements:
     *
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155BatchReceived} and return the
     * acceptance magic value.
     */
    function _safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    )
        internal
        virtual
    {
        require(ids.length == amounts.length, "ids.length != amounts.length");
        require(to != address(0), "transfer to the zero address");

        address operator = _msgSender();

        for (uint256 i = 0; i < ids.length; ++i) {
            uint256 id = ids[i];
            uint256 amount = amounts[i];

            uint256 fromBalance = _balances[id][from];
            require(fromBalance >= amount, "insufficient balance");
            unchecked {
                _balances[id][from] = fromBalance - amount;
            }
            _balances[id][to] += amount;
        }

        emit TransferBatch(operator, from, to, ids, amounts);

        _doSafeBatchTransferAcceptanceCheck(operator, from, to, ids, amounts, data);
    }

    /**
     * @dev Sets a new URI for all token types, by relying on the token type ID
     * substitution mechanism
     * https://eips.ethereum.org/EIPS/eip-1155#metadata[defined in the EIP].
     *
     * By this mechanism, any occurrence of the `\{id\}` substring in either the
     * URI or any of the amounts in the JSON file at said URI will be replaced by
     * clients with the token type ID.
     *
     * For example, the `https://token-cdn-domain/\{id\}.json` URI would be
     * interpreted by clients as
     * `https://token-cdn-domain/000000000000000000000000000000000000000000000000000000000004cce0.json`
     * for token type ID 0x4cce0.
     *
     * See {uri}.
     *
     * Because these URIs cannot be meaningfully represented by the {URI} event,
     * this function emits no events.
     */
    function _setURI(string memory newuri) internal virtual {
        _uri = newuri;
    }

    /**
     * @dev Creates `amount` tokens of token type `id`, and assigns them to `to`.
     *
     * Emits a {TransferSingle} event.
     *
     * Requirements:
     *
     * - Should only be called by
     *      - _mint(...)
     *      - LiquidityOcean._computeOutputAmount(...)
     *      - LiquidityOcean._computeInputAmount(...)
     *      - LiquidityOcean._grantFeeToOcean(...)
     *
     * - When called by _mint(...) this function complies with the ERC-1155 spec
     * - When called by the LiquidityOcean functions, this function breaks the
     *      ERC-1155 spec deliberately.  The contract that is the target of a
     *      compute*() call can revert the transaction if it does not want to
     *      receive the tokens, so the safeTransferAcceptanceCheck is redundant.
     *      The address receiving the fees (immutable DAO) is required to handle
     *      receiving fees without a safeTransferCheck.  By avoiding an SLOAD
     *      and an external call during the fee assignment, we save users gas.
     */
    function _mintWithoutSafeTransferAcceptanceCheck(
        address to,
        uint256 id,
        uint256 amount
    )
        internal
        returns (address)
    {
        address operator = _msgSender();

        _balances[id][to] += amount;
        emit TransferSingle(operator, address(0), to, id, amount);

        return operator;
    }

    /**
     * @dev Creates `amount` tokens of token type `id`, and assigns them to `to`.
     *
     * Emits a {TransferSingle} event.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155Received} and return the
     * acceptance magic value.
     */
    function _mint(address to, uint256 id, uint256 amount) internal virtual {
        assert(to != address(0));

        address operator = _mintWithoutSafeTransferAcceptanceCheck(to, id, amount);

        _doSafeTransferAcceptanceCheck(operator, address(0), to, id, amount, "");
    }

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {_mint}.
     *
     * Requirements:
     *
     * - `ids` and `amounts` must have the same length.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155BatchReceived} and return the
     * acceptance magic value.
     */
    function _mintBatch(address to, uint256[] memory ids, uint256[] memory amounts) internal virtual {
        assert(to != address(0));
        assert(ids.length == amounts.length);

        address operator = _msgSender();

        for (uint256 i = 0; i < ids.length; ++i) {
            _balances[ids[i]][to] += amounts[i];
        }

        emit TransferBatch(operator, address(0), to, ids, amounts);

        _doSafeBatchTransferAcceptanceCheck(operator, address(0), to, ids, amounts, "");
    }

    /**
     * @dev Destroys `amount` tokens of token type `id` from `from`
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `from` must have at least `amount` tokens of token type `id`.
     */
    function _burn(address from, uint256 id, uint256 amount) internal virtual {
        assert(from != address(0));

        address operator = _msgSender();

        uint256 fromBalance = _balances[id][from];
        require(fromBalance >= amount, "burn amount exceeds balance");
        unchecked {
            _balances[id][from] = fromBalance - amount;
        }

        emit TransferSingle(operator, from, address(0), id, amount);
    }

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {_burn}.
     *
     * Requirements:
     *
     * - `ids` and `amounts` must have the same length.
     */
    function _burnBatch(address from, uint256[] memory ids, uint256[] memory amounts) internal virtual {
        assert(from != address(0));
        assert(ids.length == amounts.length);

        address operator = _msgSender();

        for (uint256 i = 0; i < ids.length; ++i) {
            uint256 id = ids[i];
            uint256 amount = amounts[i];

            uint256 fromBalance = _balances[id][from];
            require(fromBalance >= amount, "burn amount exceeds balance");
            unchecked {
                _balances[id][from] = fromBalance - amount;
            }
        }

        emit TransferBatch(operator, from, address(0), ids, amounts);
    }

    /**
     * @dev Approve `operator` to operate on all of `owner` tokens
     *
     * Emits a {ApprovalForAll} event.
     */
    function _setApprovalForAll(address owner, address operator, bool approved) internal override {
        require(owner != operator, "Set approval for self");
        _operatorApprovals[owner][operator] = approved;
        emit ApprovalForAll(owner, operator, approved);
    }

    function _doSafeTransferAcceptanceCheck(
        address operator,
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    )
        private
    {
        if (to.isContract()) {
            try IERC1155Receiver(to).onERC1155Received(operator, from, id, amount, data) returns (bytes4 response) {
                if (response != IERC1155Receiver.onERC1155Received.selector) {
                    revert("ERC1155Receiver rejected");
                }
            } catch Error(string memory reason) {
                revert(reason);
            } catch {
                revert("non-ERC1155Receiver");
            }
        }
    }

    function _doSafeBatchTransferAcceptanceCheck(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    )
        private
    {
        if (to.isContract()) {
            try IERC1155Receiver(to).onERC1155BatchReceived(operator, from, ids, amounts, data) returns (
                bytes4 response
            ) {
                if (response != IERC1155Receiver.onERC1155BatchReceived.selector) {
                    revert("ERC1155Receiver rejected");
                }
            } catch Error(string memory reason) {
                revert(reason);
            } catch {
                revert("non-ERC1155Receiver");
            }
        }
    }
}
