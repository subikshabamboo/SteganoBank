# blockchain.py
import hashlib
import json
from datetime import datetime

class Block:
    """A single block in the blockchain"""
    
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data  # Transaction data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        """Calculate SHA-256 hash of block"""
        block_string = json.dumps({
            'index': self.index,
            'timestamp': str(self.timestamp),
            'data': self.data,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, difficulty=2):
        """Simple proof-of-work mining"""
        target = '0' * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
    
    def to_dict(self):
        """Convert block to dictionary"""
        return {
            'index': self.index,
            'timestamp': str(self.timestamp),
            'data': self.data,
            'previous_hash': self.previous_hash,
            'hash': self.hash,
            'nonce': self.nonce
        }


class AuditBlockchain:
    """Blockchain for immutable audit trail"""
    
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """Create the first block"""
        genesis_block = Block(0, datetime.now(), "Genesis Block - SteganoSecure System Initialized", "0")
        genesis_block.mine_block()
        self.chain.append(genesis_block)
    
    def get_latest_block(self):
        """Get the last block in chain"""
        return self.chain[-1]
    
    def add_transaction(self, transaction_type, user, details):
        """Add a new transaction to pending"""
        transaction = {
            'type': transaction_type,
            'user': user,
            'details': details,
            'timestamp': str(datetime.now())
        }
        self.pending_transactions.append(transaction)
    
    def mine_pending_transactions(self):
        """Mine all pending transactions into a new block"""
        if not self.pending_transactions:
            return None
        
        # Create new block with all pending transactions
        new_block = Block(
            index=len(self.chain),
            timestamp=datetime.now(),
            data=self.pending_transactions.copy(),
            previous_hash=self.get_latest_block().hash
        )
        
        # Mine the block (proof of work)
        new_block.mine_block(difficulty=2)
        
        # Add to chain
        self.chain.append(new_block)
        
        # Clear pending transactions
        self.pending_transactions = []
        
        return new_block
    
    def is_chain_valid(self):
        """Verify blockchain integrity"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Check if current block's hash is correct
            if current_block.hash != current_block.calculate_hash():
                return False
            
            # Check if previous hash matches
            if current_block.previous_hash != previous_block.hash:
                return False
        
        return True
    
    def get_chain(self):
        """Get entire blockchain as list of dicts"""
        return [block.to_dict() for block in self.chain]
    
    def get_transactions_by_user(self, username):
        """Get all transactions for a specific user"""
        user_transactions = []
        for block in self.chain[1:]:  # Skip genesis
            if isinstance(block.data, list):
                for transaction in block.data:
                    if transaction.get('user') == username:
                        user_transactions.append({
                            'block_index': block.index,
                            'block_hash': block.hash,
                            'transaction': transaction
                        })
        return user_transactions
    
    def get_chain_stats(self):
        """Get blockchain statistics"""
        total_transactions = 0
        for block in self.chain[1:]:
            if isinstance(block.data, list):
                total_transactions += len(block.data)
        
        return {
            'total_blocks': len(self.chain),
            'total_transactions': total_transactions,
            'chain_valid': self.is_chain_valid(),
            'latest_hash': self.get_latest_block().hash
        }


# Global blockchain instance (in production, use database)
audit_chain = AuditBlockchain()