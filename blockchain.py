#Chris Smith

###############||
#####Unchanged#||
###############\/

def str_to_bitarray(s):
    # Converts string to a bit array.
    bitArr = list()
    for byte in s:
        bits = bin(byte)[2:] if isinstance(byte, int) else bin(ord(byte))[2:]
        while len(bits) < 8:
            bits = "0"+bits  # Add additional 0's as needed
        for bit in bits:
            bitArr.append(int(bit))
    return(bitArr)

def bitarray_to_str(bitArr):
    # Converts bit array to string
    result = ''
    for i in range(0,len(bitArr),8):
        byte = bitArr[i:i+8]
        s = ''.join([str(b) for b in byte])
        result = result+chr(int(s,2))
    return result

def xor(a, b):
    # xor function - This function is complete
    return [i^j for i,j in zip(a,b)]

def VernamEncrypt(binKey,block):
    # Vernam cipher
    if (len(binKey) != len(block)):
        raise Exception("Key is not same size as block")
    return xor(binKey,block)

def VernamDecrypt(binKey,block):
    # Basically a Vernam cipher.  Note it is
    # exactly the same as encryption.
    return VernamEncrypt(binKey,block)

###############/\
#####Unchanged#||
###############||

class BlockChain():

    # Modes
    CBC = 0
    PCBC = 1
    CFB = 2
    
    def __init__(self,keyStr,ivStr,encryptMethod,decryptMethod,mode):
        self.encryptBlk = encryptMethod
        self.decryptBlk = decryptMethod
        self.mode = mode
        # Any other variables you might need
        self.keyStr=keyStr
        self.ivStr=ivStr

    def encrypt(self,msg):
        cipherBlks = list()
        blks=self.getBlocks(msg)                #Get the msg in a list of blocks with padding
        if self.mode==0:
            out=str_to_bitarray(self.ivStr)
            for clear in blks:
                if len(clear)==8:               
                    temp=xor(str_to_bitarray(clear),out)
                    out=self.encryptBlk(str_to_bitarray(self.keyStr),temp)
                    cipherBlks.append(bitarray_to_str(out))
        elif self.mode==1:
            instr=str_to_bitarray(self.ivStr)
            for clear in blks:
                if len(clear)==8:
                    out=self.encryptBlk(str_to_bitarray(self.keyStr),xor(instr,str_to_bitarray(clear)))
                    instr=xor(out,str_to_bitarray(clear))
                    cipherBlks.append(bitarray_to_str(out))
        elif self.mode==2:
            instr=str_to_bitarray(self.ivStr)
            for clear in blks:
                if len(clear)==8:
                    out=self.encryptBlk(str_to_bitarray(self.keyStr),instr)
                    instr=xor(str_to_bitarray(clear),out)
                    cipherBlks.append(bitarray_to_str(instr))
        return cipherBlks

    def decrypt(self,cipherBlks):
        # Takes a list of cipher blocks and returns the
        # message. Again, decryption is based on mode.
        msg = list()
        if self.mode==0:
            instr=str_to_bitarray(self.ivStr)
            for blk in cipherBlks:
                out=self.decryptBlk(str_to_bitarray(self.keyStr),str_to_bitarray(blk))
                temp=xor(instr,out)
                instr=str_to_bitarray(blk)
                msg.append(bitarray_to_str(temp))
        elif self.mode==1:
            instr=str_to_bitarray(self.ivStr)
            for blk in cipherBlks:
                out=self.decryptBlk(str_to_bitarray(self.keyStr),str_to_bitarray(blk))
                temp=xor(instr,out)
                instr=xor(str_to_bitarray(blk),temp)
                msg.append(bitarray_to_str(temp))
        elif self.mode==2:
            instr=str_to_bitarray(self.ivStr)
            for blk in cipherBlks:
                out=self.encryptBlk(str_to_bitarray(self.keyStr),instr)
                temp=xor(out,str_to_bitarray(blk))
                instr=str_to_bitarray(blk)
                msg.append(bitarray_to_str(temp))
        msg=self.unpad(msg)                                     #Remove any message padding
        return msg

    def getBlocks(self, msg):                                   #Split msg into 8 byte blocks
        #size=len(msg)
        full=int(len(msg)/8)
        part=len(msg)%8
        ret=[]
        x=0
        for ea in range(full+part):
            ret.append(msg[x:x+8])
            x+=8
        ret=self.pad(ret)                                       #Apply padding
        return ret

    def pad(self, blks):
        #return list of blks padded using ANSI X.923
        #last 8 byte block is padded
        #last byte is padding info
        infobytes=['\x00','\x01','\x02','\x03','\x04','\x05','\x06','\x07','\x08']#info bytes
        ret=[]
        size=len(blks)
        last=blks[size-1]
        fill=8-len(last)                                        #amount of needed padding
        for ea in range(fill-1):                                #add the padding zeros
            last+='\x00'
        last+=infobytes[fill]                                   #add the info byte
        blks[size-1]=last                                       #replace the last 8 byte block
        return blks                                             #return the new list of blks

    def unpad(self, blks):
        #check the last block for padding info
        #remove padding and info byte
        size=len(blks)
        last=blks[len(blks)-1]                                  #only concerned with the last 8 byte block
        info=last[7]                                            #read the last byte of the last block
        if info=='\x08':
            blks=blks[:size-1]
        if info=='\x07':
            blks[size-1]=blks[size-1][0]
        if info=='\x06':
            blks[size-1]=blks[size-1][:2]
        if info=='\x05':
            blks[size-1]=blks[size-1][:3]
        if info=='\x04':
            blks[size-1]=blks[size-1][:4]
        if info=='\x03':
            blks[size-1]=blks[size-1][:5]
        if info=='\x02':
            blks[size-1]=blks[size-1][:6]
        if info=='\x01':
            blks[size-1]=blks[size-1][:7]
        return blks

if __name__ == '__main__':
    #Tester:
    #Tests each mode and uses the msg string which requires padding
    #Cleans up the output by printing in a nicer single line
    key = "secret_k"
    iv = "whatever"
    msg = "This is my message.  There are many like it but this one is mine."
    output =""

    #CBC testing
    blkChain = BlockChain(key,iv,VernamEncrypt,VernamDecrypt,BlockChain.CBC)
    cipherblks = blkChain.encrypt(msg)
    print("\nCBC Ciphertext:")
    for blk in cipherblks:
        print(blk)
    print("CBC Decrypted:")
    dmsg = blkChain.decrypt(cipherblks)
    for ea in dmsg:
        output+=ea
    print(output)

    #PCBC testing
    blkChain = BlockChain(key,iv,VernamEncrypt,VernamDecrypt,BlockChain.PCBC)
    cipherblks = blkChain.encrypt(msg)
    output =""
    print("\nPCBC Ciphertext:")
    for blk in cipherblks:
        print(blk)
    print("PCBC Decrypted:")
    dmsg = blkChain.decrypt(cipherblks)
    for ea in dmsg:
        output+=ea
    print(output)

    #CFB testing
    blkChain = BlockChain(key,iv,VernamEncrypt,VernamDecrypt,BlockChain.CFB)
    cipherblks = blkChain.encrypt(msg)
    output =""
    print("\nCFB Ciphertext:")
    for blk in cipherblks:
        print(blk)
    print("CFB Decrypted:")
    dmsg = blkChain.decrypt(cipherblks)
    for ea in dmsg:
        output+=ea
    print(output)
