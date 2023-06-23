# XOR-Encryption-Breaker
XOR Encrypt text using the encryption mode or break XOR encryption using the break mode. 

Break works by iterating through potential keys and performing statistical analysis for the best match. If the output looks close but not quite there the issue may be the case of the key. Ex. 'a' vs 'A'

This small change makes the difference between "tHISISATEST♫mOREWORDSANDLETTERSFORINCREASEDACCURACYTOSEEIFTHISMAKESADIFFERENCE" and 
"This is a test. More words and letters for increased accuracy to see if this makes a difference "

Statistical analysis shows the correct ratio of letters however it is less human readable.
