import java.security.PublicKey;
import java.util.ArrayList;

public class TxHandler {
	
	UTXOPool _pool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent 
     * transaction outputs) is {@code utxoPool}. This should make a copy of 
     * utxoPool by using the UTXOPool(UTXOPool uPool) constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        _pool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the 
     * sum of its output values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
    	// This accomplishes (1) and (3)
    	boolean outputsAreValid = checkOutputs(tx);
    	// This accomplishes (2)
    	boolean signaturesAreValid = verifySignatures(tx);
    	// This accomplishes (4)
    	boolean nonnegativeOutputs = checkOutputsNegative(tx);
    	// This accomplishes (5) 
    	boolean inputSumGreater = checkInputSumGreater(tx);
    			
    	return outputsAreValid && signaturesAreValid && nonnegativeOutputs
    			&& inputSumGreater;
    }
    
    private boolean checkInputSumGreater(Transaction tx){
    	double outputSum = 0.0;
    	for(Transaction.Output o : tx.getOutputs())
    		outputSum += o.value;
    	
    	double inputSum = 0.0;
    	for(Transaction.Input i : tx.getInputs()){
    		UTXO utxo = new UTXO(i.prevTxHash, i.outputIndex);
    		// bail out if this is null; we need it non null
    		if(_pool.getTxOutput(utxo) == null)
    			return false;
    		
    		inputSum += _pool.getTxOutput(utxo).value;
    	}

    	return inputSum >= outputSum;
    }
    
    private boolean checkOutputsNegative(Transaction tx){
    	for(Transaction.Output o : tx.getOutputs()){
    		if(o.value < 0) return false;
    	}
    	return true;
    }
 
    private boolean verifySignatures(Transaction tx){
    	for(int inputIndex = 0; inputIndex < tx.getInputs().size(); inputIndex++){
    		Transaction.Input i = tx.getInput(inputIndex);
    		// first thing we need is the signature
    		byte[] signature = i.signature;
    		// second, get the message - this is the signed message???
    		byte[] message = tx.getRawDataToSign(inputIndex);
    		// third, get the PublicKey from OUR POOL and check it against
    		// the INCOMING INPUT
    		UTXO utxo = new UTXO(i.prevTxHash, i.outputIndex);
    		// bail out if these are null; we need them to be non null
    		if(_pool.getTxOutput(utxo) == null || message == null  
    				|| signature == null){
    			return false;
    		}
    		
    		PublicKey pubKee = _pool.getTxOutput(utxo).address;
    		
    		// last, run it all through Crypto.verifySignature
    		// return false if the input's signature is not valid
    		if (!Crypto.verifySignature(pubKee, message, signature))
    			return false;    		
    	}
    	return true;
    }
    
    private boolean checkOutputs(Transaction tx){
    	// initialize a check pool to keep track of UTXO's we've already checked
    	// for each transaction input, create a UTXO
    	// check if the UTXO is in the pool and has already been looked at
    	// then add the present UTXO to the pool
    	UTXOPool checkPool = new UTXOPool();
    	for(Transaction.Input input : tx.getInputs()){
    		UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
    		if(!_pool.contains(utxo) || checkPool.contains(utxo))
    			return false;
    		checkPool.addUTXO(utxo, null);
    	}
    	return true;
    }
    
    /**
     * Handles each epoch by receiving an unordered array of proposed 
     * transactions, checking each transaction for correctness, returning a 
     * mutually valid array of accepted transactions, and updating the current 
     * UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        Transaction[] retVal = new Transaction[possibleTxs.length];
        for(int i = 0; i < retVal.length; i++){
        	if(isValidTx(possibleTxs[i])){
        		retVal[i] = possibleTxs[i];
        	}
        }
        // TODO: Update the UTXO pool?
    	return retVal;
    }
}













