'''
Descripttion: 
version: 
Author: Martin
FilePath: \Martin_Code\Python\密码学\my_sm3.py
Date: 2022-05-18 16:41:45
LastEditTime: 2022-05-19 09:31:27
'''
from tokenize import group
from gmssl import sm3

IV="7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e"
#print(IV.replace(" ", ""))
IV = int(IV.replace(" ", ""), 16)
print(IV)
#print(IV)
a = []
for i in range(0, 8):
    a.append(0)
    a[i] = (IV >> ((7 - i) * 32)) & 0xFFFFFFFF
    print(IV >> ((7 - i) * 32))
    # break
IV = a
#print(IV)

#初始化T_j
T_j = []
for i in range(0, 16):
    T_j.append(0)
    T_j[i] = 0x79cc4519
for i in range(16, 64):
    T_j.append(0)
    T_j[i] = 0x7a879d8a


class SM3:
    #构建一个类，调用ret()返回散列值
    def __init__(self,message) -> None:
        self.msg = message
        self.msg_byte = self.str2byte()
        self.sm3_hash = self.hash_msg(self.msg_byte)
        print(message+'对应的哈希值为：',self.sm3_hash,sep='')
        
    # 字符串转成byte数组
    def str2byte(self):
        ml = len(self.msg)
        msg_byte = []
        msg_bytearray = self.msg.encode('utf-8')  
        #print(type(msg_bytearray))   #字符类型
        for i in range(ml):
            msg_byte.append(msg_bytearray[i])
        return msg_byte
    
    # 以下msg 为 self.msg_byte
    def hash_msg(self,msg):
        # print('msg',msg)
        len1 = len(msg)
        reserve1 = len1 % 64
        msg.append(0x80)
        reserve1 = reserve1 + 1
        # 56-64, add 64 byte
        range_end = 56
        if reserve1 > range_end: #前面超出56字节
            range_end = range_end + 64
            #补0
        for i in range(reserve1, range_end):
            msg.append(0x00)

         
        bit_length = (len1) * 8
        bit_length_str = [bit_length % 0x100]  # mod 2的64次方 256 2的8次方
        for i in range(7):
            bit_length = int(bit_length / 0x100)
            bit_length_str.append(bit_length % 0x100)
        for i in range(8):
            msg.append(bit_length_str[7-i])
        #print("msg",msg)
        
        group_count = round(len(msg) / 64)
        #print(group_count)
        # 512一组的列表
        B = []
        for i in range(0,group_count):
            B.append(msg[i*64:(i+1)*64])
        #print("B",B)
        
        V = []
        V.append(IV)
        for i in range(0,group_count):
            V.append(self.CF(V[i],B[i]))
        
        y = V[i+1]
        result = ""
        for i in y:
            result = '%s%08x' % (result, i)
        return result
    
    # 压缩函数 CF
    def CF(self,V_i,B_i):
        # 初始化W0-W15
        W = []
        for i in range(16):
            weight = 0x1000000 #64  
            data = 0
            for k in range(i*4,(i+1)*4):
                data = data + B_i[k]*weight 
                # print(B_i[k])
                weight = int(weight/0x100) #4
            W.append(data)
            # print(W)
    
        for j in range(16, 68):
            W.append(0)
            W[j] = self.P_1(W[j-16] ^ W[j-9] ^ (self.rotate_left(W[j-3], 15))) ^ (self.rotate_left(W[j-13], 7)) ^ W[j-6]
            #print(W[j])
            #整数格式化8位字符串
            str1 = "%08x" % W[j]
            #print(str1)
        #初始化 W_1
        W_1 = []
        for j in range(0, 64):
            W_1.append(0)
            W_1[j] = W[j] ^ W[j+4]
            str1 = "%08x" % W_1[j]

        A, B, C, D, E, F, G, H = V_i
        """
        print "00",
        out_hex([A, B, C, D, E, F, G, H])
        """

        #压缩函数
        for j in range(0, 64):
            SS1 = self.rotate_left(((self.rotate_left(A, 12)) + E + (self.rotate_left(T_j[j], j))) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ (self.rotate_left(A, 12))
            TT1 = (self.FF_j(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF
            TT2 = (self.GG_j(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = self.rotate_left(B, 9)
            B = A
            A = TT1
            H = G
            G = self.rotate_left(F, 19)
            F = E
            E = self.P_0(TT2)

            A = A & 0xFFFFFFFF
            B = B & 0xFFFFFFFF
            C = C & 0xFFFFFFFF
            D = D & 0xFFFFFFFF
            E = E & 0xFFFFFFFF
            F = F & 0xFFFFFFFF
            G = G & 0xFFFFFFFF
            H = H & 0xFFFFFFFF
            """
            str1 = "%02d" % j
            if str1[0] == "0":
                str1 = ' ' + str1[1:]
            print str1,
            out_hex([A, B, C, D, E, F, G, H])
            """

        V_i_1 = []
        V_i_1.append(A ^ V_i[0])
        V_i_1.append(B ^ V_i[1])
        V_i_1.append(C ^ V_i[2])
        V_i_1.append(D ^ V_i[3])
        V_i_1.append(E ^ V_i[4])
        V_i_1.append(F ^ V_i[5])
        V_i_1.append(G ^ V_i[6])
        V_i_1.append(H ^ V_i[7])
        return V_i_1
    
    # 置换函数，P_1
    def P_1(self,X):
        return X ^ (self.rotate_left(X, 15)) ^ (self.rotate_left(X, 23))
    
    # 循环左移
    def rotate_left(self,a,k):
        k = k % 32
        return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k))

    # 布尔函数 FF_j
    def FF_j(self,X, Y, Z, j):
        if 0 <= j and j < 16:
            ret = X ^ Y ^ Z
        elif 16 <= j and j < 64:
            ret = (X & Y) | (X & Z) | (Y & Z)
        return ret
    
    # 布尔函数 GG_j
    def GG_j(self,X, Y, Z, j):
        if 0 <= j and j < 16:
            ret = X ^ Y ^ Z
        elif 16 <= j and j < 64:
            #ret = (X | Y) & ((2 ** 32 - 1 - X) | Z)
            ret = (X & Y) | ((~ X) & Z)
        return ret

    # 置换函数，P_0
    def P_0(self,X):
        return X ^ (self.rotate_left(X, 9)) ^ (self.rotate_left(X, 17))
    
    #
    def ret(self):
        return self.sm3_hash

if  __name__ == '__main__':
    message = 'Today is suitable for learning cryptography'
    mysm3 = SM3(message)


    from gmssl import sm3, func
    strs = 'Today is suitable for learning cryptography'
    str_b = bytes(strs, encoding='utf-8')
    result = sm3.sm3_hash(func.bytes_to_list(str_b))
    print("标准:",result)