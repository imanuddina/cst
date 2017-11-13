import sys

#some defines
MAX_FW_SESSION_NUM=2**8
MPE_HAL_NO_FREE_ENTRY=0x8000
MAX_SEARCH_ITRN=15
TBL_IDX=0
TBL_VAL=1
TBL_FPTR=2
TBL_NPTR=3
TBL_KEY=4
FN_PTR_DEF=MAX_FW_SESSION_NUM-1
INSERT_SESSION=0
MAX_ENTRY_ERROR=1

def mpe_cal_hash(sip, dip, sp, dp, ex):
  s3, s2, s1, s0 = sip.split('.')
  d3, d2, d1, d0 = dip.split('.')
  p0 = int(sp[2:4], 16)
  p1 = int(sp[4:],  16)
  p2 = int(dp[2:4], 16)
  p3 = int(dp[4:] , 16)
  # print hex(int(s3)), hex(int(s2)), hex(int(s1)), hex(int(s0))
  L = [int(s3), int(s2), int(s1), int(s0), int(d3), int(d2), int(d1), int(d0),
       p0, p1, p2, p3, int(ex[2:], 16)]
  return L

def mpe_hal_crcmsb(b):
  # https://www.lammertbies.nl/comm/info/crc-calculation.html
  # input type: hex
  # method: crc-ccitt (xmodem)
  crc=0
  i=0
  poly=0x1021
  for byte in b:
    crc ^= (byte << 8)
    for i in range(8):
      if(crc & 0x8000):
        crc = (crc << 1) ^ poly
      else:
        crc <<= 1
      crc = crc & 0xFFFF
  #print hex(crc)
  return crc

def init_tbl(tbl):
  # Init table as list
  # [idx, Valid,FirstPtr, NextPtr, Key]
  # Initial values:
  #    Valid    = 0
  #    FirstPtr = MAX_FW_SESSION_NUM-1
  #    NextPtr  = MAX_FW_SESSION_NUM-1
  for i in range(MAX_FW_SESSION_NUM):
    tbl[i]=[i, 0, MAX_FW_SESSION_NUM-1, MAX_FW_SESSION_NUM-1]

def find_free_index(tbl):
  counter=0
  while(counter < MAX_FW_SESSION_NUM):
    if(not tbl[counter][TBL_VAL]):
      return counter
    counter+=1
  # Table has no free index
  return MPE_HAL_NO_FREE_ENTRY

def insert_key(ses, hash_val, tbl):
  FoundLoc=0
  counter=0
  locate_method=0  # to choose better insertion method
  hash_index = hash_val & (MAX_FW_SESSION_NUM-1)
  print hex(hash_val), hex(hash_index)
  
  # Check if number of entries with same hash index value have not exceeded
  # maximum allowed i.e MAX_SEARCH_ITRN
  tmp = tbl[hash_index][TBL_FPTR]
  if(FN_PTR_DEF == tmp):
    print "First entry with hash_index = ", hex(hash_index)
  else:
     print "Locate similar entries ..."
     if(locate_method):  # see log2.txt
       while(1):
          previous = tmp
          tmp = tbl[tmp][TBL_NPTR]
          counter+=1
          print counter, previous
          if(previous == tmp):
            break
     else: # older way see log1.txt
       while(tmp != tbl[tmp][TBL_NPTR]):
         print tmp, tbl[tmp][TBL_NPTR]
         tmp = tbl[tmp][TBL_NPTR]
         counter+=1
       counter+=1  
  print "Iteration count: " , counter
  
  if(counter > MAX_SEARCH_ITRN):
    print "Max iteration achieved"
    return FoundLoc
    
  # Check if location is free i.e loc.valid = 0
  if((not tbl[hash_index][TBL_VAL]) and (FN_PTR_DEF==tbl[hash_index][TBL_FPTR])):
    tbl[hash_index][TBL_FPTR] = hash_index
    tbl[hash_index][TBL_NPTR] = hash_index
    free_index = hash_index
    print "First time use, preferred location"
    FoundLoc=1
  elif((tbl[hash_index][TBL_VAL]) and (FN_PTR_DEF==tbl[hash_index][TBL_FPTR])):
    print "First entry but its preferred location is not free"
    # Keep looking for empty slot, starts from first location
    free_index = find_free_index(tbl)
    if(MPE_HAL_NO_FREE_ENTRY == free_index):
      print "FW compare table is full, no insertion made !"
      return FoundLoc
    tbl[free_index][TBL_NPTR] = free_index
    tbl[hash_index][TBL_FPTR] = free_index
    print "free_index = ", free_index
    FoundLoc=1
  elif((tbl[hash_index][TBL_VAL]) and (FN_PTR_DEF!=tbl[hash_index][TBL_FPTR])):
    print "Found at least one similar entry"
    # Keep looking for empty slot, starts from first location
    free_index = find_free_index(tbl)
    if(MPE_HAL_NO_FREE_ENTRY == free_index):
      print "FW compare table is full, no insertion made !"
      return FoundLoc
    tbl[free_index][TBL_NPTR] = tbl[hash_index][TBL_FPTR]
    tbl[hash_index][TBL_FPTR] = free_index
    print "free_index = ", free_index
    FoundLoc=1
   
  if(1==FoundLoc):
    tbl[free_index][TBL_VAL]=1
    tbl[free_index].extend(ses)
  return FoundLoc

def iterate_keys(hash_index,  tbl):
  # It just iterates each possible index in the table
  # Read from 0 till MAX_FW_SESSION_NUM-1
  counter=0
  
  if(tbl[hash_index][TBL_VAL]):
     tmp = tbl[hash_index][TBL_FPTR]     
     print "Start iterate ..."
     while(1):
        previous = tmp
        tmp = tbl[tmp][TBL_NPTR]
        counter+=1
        print counter, previous
        if(previous == tmp):
          break
     #print 'hash_index[', hex(hash_index), '] has:', counter, 'entry'
     print "hash_index 0x%x has %d entry"%(hash_index, counter)
  else:
    print "No entry with hash_index = ", hex(hash_index)     
        
def delete_key(entry_index, ses, tbl):
  counter = 0
  hash_start = mpe_hal_crcmsb(ses)
  hash_start &= (MAX_FW_SESSION_NUM-1)
  if(MAX_FW_SESSION_NUM-1 < entry_index):
    print "Entry index ", idx, "is wrong for", hash_start
  
  # Check if session at index is valid
  if(tbl[entry_index][TBL_VAL]):
     previous = hash_start
     index = tbl[previous][TBL_FPTR]     
     print "Start locate the entry ..."
     while(entry_index != index):
        # Is it necessary to check maximum iteration search?
        if(counter > MAX_SEARCH_ITRN):
           print "Entry index is wrong for hash:" , hex(hash_start)
           return MAX_ENTRY_ERROR
        previous = index
        index = tbl[index][TBL_NPTR]
        counter+=1
        
     sta = tbl[hash_start][TBL_FPTR]
     nxt = tbl[entry_index][TBL_NPTR]

     if(sta == entry_index):
       if((entry_index == hash_start) and (nxt == hash_start)):
         print "First and single entry deleted"
         tbl[hash_start][TBL_FPTR] = FN_PTR_DEF
       else:
         print "Entry at FPTR deleted, but it is not single entry" 
         tbl[hash_start][TBL_FPTR] = nxt 
     elif(entry_index == nxt):
       print "First recorded entry deleted"  # This is the hash_start first recorded entry
       tbl[previous][TBL_NPTR] = previous
     else:
       print "Middle entry deleted"
       tbl[previous][TBL_NPTR] = nxt
       
     tbl[entry_index][TBL_NPTR] = FN_PTR_DEF    
     tbl[entry_index][TBL_VAL] = 0
  else:
     print entry_index, ": no Item to Delete!"
        
def print_tbl(tbl):
  for i in range(MAX_FW_SESSION_NUM):
    #if(1==tbl[i][TBL_VAL]):
      # idx, Valid,FirstPtr, NextPtr, Key
      if(tbl[i][TBL_KEY:]):  # print five tupples if available
        print tbl[i][TBL_IDX], tbl[i][TBL_VAL], tbl[i][TBL_FPTR], tbl[i][TBL_NPTR], tbl[i][TBL_KEY:]
      else:
        print tbl[i][TBL_IDX], tbl[i][TBL_VAL], tbl[i][TBL_FPTR], tbl[i][TBL_NPTR]
      
def checkCRC(message):
    # https://stackoverflow.com/questions/25239423/crc-ccitt-16-bit-python-manual-calculation
    #CRC-16-CITT poly, the CRC sheme used by ymodem protocol
    poly = 0x1021
    #16bit operation register, initialized to zeros
    reg = 0xFFFF

    mask = 0xF8
    mask>>=1
    print hex(mask)


    #for each bit in the message
    for byte in message:
        mask = 0x80
        #print byte
        while(mask > 0):
            #left shift by one
            reg<<=1
            #input the next bit from the message into the right hand side of the op reg
            if (byte) & mask:   
                reg += 1
            mask>>=1
            #if a one popped out the left of the reg, xor reg w/poly
            if reg > 0xffff:            
                #eliminate any one that popped out the left
                reg &= 0xffff           
                #xor with the poly, this is the remainder
                reg ^= poly
    #print reg            
    return reg
  
def main():
    # The main code of the program goes here
    v=mpe_cal_hash('192.168.10.1', '100.80.60.20', '0x500c', '0x6011', '0x21')
    #for data in v:
    #  print hex(data)
    #print hex(checkCRC(v)) # not intended
    mpe_hal_crcmsb(v)      # this is python script translated from C

    v=mpe_cal_hash('192.168.0.1', '192.168.128.1', '0x5001', '0x6004', '0x0')
    hashv=mpe_hal_crcmsb(v)

    # "Allocate" the FW compare table area
    pIp4CmpTbl=list(range(MAX_FW_SESSION_NUM))
    # Initialise default value for table fields
    init_tbl(pIp4CmpTbl)

    ##insert_key(v, hashv, pIp4CmpTbl)
    ##insert_key(v, hashv, pIp4CmpTbl)
    ##insert_key(v, hashv, pIp4CmpTbl)

    # Create 256 entries
    #for i in range(0,100):
    # Notes most verification below using range (0, 100)
    # e.g delete, iterate
    for i in range(0, 256):
      sp=0x5000+i  # vary the source port
      xp=(0x0+i)%4 # vary the extension 
      v=mpe_cal_hash('192.168.0.1', '192.168.128.1', hex(sp), '0x6004', hex(xp))
      hashv=mpe_hal_crcmsb(v)  
      success=insert_key(v, hashv, pIp4CmpTbl)
      if(not success): print "insertion ", v, "failed"
    print_tbl(pIp4CmpTbl)



    #Delete single entry VERIFIED



    # Delete entry at hash_index VERIFIED (first recorded entry is last entry in delete iteration)
    #v=mpe_cal_hash('192.168.0.1', '192.168.128.1', '0x5002', '0x6004', '0x2')
    #delete_key(42, v, pIp4CmpTbl)

    # Delete entry at FPTR VERIFIED
    #v=mpe_cal_hash('192.168.0.1', '192.168.128.1', '0x5038', '0x6004', '0x0')
    #delete_key(43, v, pIp4CmpTbl)

    # Delete entry in the middle VERIFIED
    #v=mpe_cal_hash('192.168.0.1', '192.168.128.1', '0x5025', '0x6004', '0x1')
    #delete_key(22, v, pIp4CmpTbl)

    # Delete entry in the middle VERIFIED
    #v=mpe_cal_hash('192.168.0.1', '192.168.128.1', '0x501f', '0x6004', '0x3')
    #delete_key(16, v, pIp4CmpTbl)

    # Delete entry when index and hash_val is mismatch VERIFIED
    #v=mpe_cal_hash('192.168.0.1', '192.168.128.1', '0x501f', '0x6004', '0x0')
    #delete_key(16, v, pIp4CmpTbl)

    # ====================================
    # VERIFIED
    iterate_keys(167, pIp4CmpTbl)

    # Delete entry at hash_index VERIFIED (first recorded entry is last entry in delete iteration)
    #v=mpe_cal_hash('192.168.0.1', '192.168.128.1', '0x500d', '0x6004', '0x1')
    #delete_key(167, v, pIp4CmpTbl)

    # Delete entry at FPTR VERIFIED
    #v=mpe_cal_hash('192.168.0.1', '192.168.128.1', '0x5037', '0x6004', '0x3')
    #delete_key(41, v, pIp4CmpTbl)

    # ====================================

    # hash_index = 9 has two entries but first recorded entry is not at
    # preferred location
    # VERIFIED
    iterate_keys(9, pIp4CmpTbl)


    # Delete first recorded entry VERIFIED
    #v=mpe_cal_hash('192.168.0.1', '192.168.128.1', '0x5041', '0x6004', '0x1')
    #delete_key(52, v, pIp4CmpTbl)

    # Delete last entry VERIFIED
    #v=mpe_cal_hash('192.168.0.1', '192.168.128.1', '0x505c', '0x6004', '0x0')
    #delete_key(68, v, pIp4CmpTbl)

    # ====================================

    # Print table
    #print_tbl(pIp4CmpTbl)

    #Delete inexist entry VERIFIED (since table only has 100 entries)
    #v=mpe_cal_hash('192.168.0.1', '192.168.128.1', '0x50FF', '0x6004', '0x3')
    #delete_key(255, v, pIp4CmpTbl)
    #print_tbl(pIp4CmpTbl)

    # No entry at index=80 since if we populate 100 entries
    # VERIFIED
    #iterate_keys(80, pIp4CmpTbl)

# this code calls the main function to get everything started. The condition in this
# if statement evaluates to True when the module is executed by the interpreter, but
# not when it is imported into another module.
if __name__ == "__main__":
    main()
