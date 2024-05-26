#pragma pack(push, 1)  
#define MAC_ADDR_LEN 6

struct radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
}; // 4 + 2 + 2 = 8
// void printMacAddr(char mac[MAC_ADDR_LEN]){
//     for(int i=0; i < MAC_ADDR_LEN; i++){
//         printf("%c", )
//     }
// }

struct BeaconFrmae{
    uint16_t frameControlField;
    uint16_t duration;
    uint8_t DestinationAddr[MAC_ADDR_LEN];
    uint8_t SourceAddr[MAC_ADDR_LEN];
    uint8_t BSSID[MAC_ADDR_LEN];
    uint16_t SequenceNumber;
};

struct BeaconBody{
    u_int8_t FiexedParm[12];
    unsigned char tag_value[];
};


#pragma pack(pop)
