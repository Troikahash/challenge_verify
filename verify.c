/*
 * Troika Challenge
 *
 * This code can be used to verify a solution for the Troika cryptanalysis
 * competition (https://troika.cyber-crypt.com).
 *
 * Copyright (C) 2018 Cybercrypt A/S <www.cyber-crypt.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "troika.h"

char tryte_lookup[27] = "0ABCDEFGHIJKLMNOPQRSTUVWXYZ";

char preimage_challenges[12][81] = {
    "WAMSUZAQROHUKCAKZQHLIWJJTAZMINYEKDXGBEGIVFSTFNVWWTPALOXSWFODWJAYOYDCPUDUGH0IYHJXJ",
    "IZTMEDAALIVYGWUXSPMMV0YNKEPWPFUVNTQWMNYFNDRNZTCFCHHJFTXEDEC0MMOKDZWDHPDQPMMASBWLE",
    "RPADZBVY0CWADCFNUQKGRAKBVMAHWQYLIHXSHDFMSOCXBPZ0IKRZNB0RTWSWK0K0HHWVLVDNS0YRENGMM",
    "JQXBQOCKDLKPYOOQRNVAJATKMNCIHRLOGWMMULRLWNKIYVAQQPVKCWRLEGLLJ0JPMWP0MZEMUFSXTCNYK",
    "YESFCNIOMTLMFGKJKQWDMEOTIBRPGRXMIIWGOGVH0IEUUNNY0MHDTYFXNWPUCLCNZRGYCLWCJAA0N0Q0F",
    "UFGRDN0VNZRHUMOPFRNXZVSWHNJESVMTIURCVHOXE0TBPCVANDFWJRDDW0HTJKKJHIJOWYVMIN0LYPRHA",
    "0SPZYCRZUQFZCRVUMGAJ0LZSPOANLRMDBFNMOORWZOGOVYXVEEMETLGAIBVULPKGZXDCDPNMZDQGTQPBS",
    "BYWRJVXXLWHJMYHLSMQRLNIRAYPJ0PTGQKPVZVNDBRWSOCUTIYTALOSSWZTZQZLCDHPUMJWOTCUITUFRT",
    "FQFBCXQLVQIZLYBYAGKFVYSJKCROKYKEUOXUSARQWDFPYHYUJOZ0SAAVIJYPSZYIYUXFTVEYEBHJYL0EM",
    "ZJOIGJCS0QECFNHKJQISORJGGETSNPVHOKZBFLRRPTIBGVHZ0RC0LXUMFORBQLCBIYADSXZZ0GQSUTJKF",
    "VDJS0KCROOSGJRCVQXHICMSQELWWTWMEZHCMGLUWECIMFWMNXQCEYOWUHZVZCWBKFXSNYN0ZXBWBMARCC",
    "LYMIIFKHLCTTOCZLCMWYDNQCFSGFWPOVQWYZMTDCRF0XIBGRYAZRW0A0PKVVTJYCASIRWKUNZYNNXFBNQ"
};

void tryte_to_trits(unsigned char *trits, unsigned char tryte)
{
    trits[2] = tryte % 3;
    tryte /= 3;
    trits[1] = tryte % 3;
    tryte /= 3;
    trits[0] = tryte % 3;
}

void tryte_string_to_trits(unsigned char *trits, const char *trytes,
                           unsigned long long len_trytes)
{
    for(unsigned long long i = 0; i < len_trytes; i++) {
        unsigned char tryte = trytes[i];
        if (tryte == '0') {
            tryte = 0;
        } else {
            tryte = trytes[i] - 64; // Convert Ascii to int value of tryte
        }
        tryte_to_trits(&trits[3*i], tryte);
    }
}

void trytes_to_trits(unsigned char *trits, const unsigned char *trytes,
                     unsigned long long len_trytes)
{
    for(unsigned long long i = 0; i < len_trytes; i++) {
        tryte_to_trits(&trits[3*i], trytes[i]);
    }
}

void print_trits(const unsigned char *trits, unsigned long long len)
{
    for(unsigned long long i = 0; i < len; i++) {
        printf("%i", trits[i]);
    }
}

void print_trits_as_trytes(const unsigned char *trits, unsigned long long len)
{
    assert(len % 3 == 0);
    for(unsigned long long i = 0; i < (len / 3); i++) {
        Tryte tmp = 9*trits[3*i] + 3*trits[3*i + 1] + trits[3*i + 2];
        printf("%c", tryte_lookup[tmp]);
    }
}

void verify_preimage(const Trit *m, unsigned long long len_m,
                     const Trit *target, unsigned long long rounds)
{
    unsigned char hash[243];

    TroikaVarRounds(hash, 243, m, len_m, rounds);

    int result = memcmp(hash, target, 243);

    if (result == 0) {
        printf("Congratulations! Send your solution to troika-challenge@googlegroups.com!\n");
        printf("---\n");
        printf("[Competition] Break Preimage %llu Rounds\n\n", rounds);
        printf("Submitters: Enter names here\n");
        printf("m: ");
        print_trits_as_trytes(m, len_m);
        printf("\nmlen: %llu\n", len_m);
        printf("H(m): ");
        print_trits_as_trytes(hash, 243);
        printf("\nSummary: Describe briefly how you broke the challenge here.\n");
    } else {
        printf("Solution not valid! Hash does not match image.\n");
    }

}

void verify_collision(Trit *m0, unsigned long long len_m0,
                      Trit *m1, unsigned long long len_m1,
                      unsigned long long rounds)
{
    unsigned char hash0[243], hash1[243];


    TroikaVarRounds(hash0, 243, m0, len_m0, rounds);
    TroikaVarRounds(hash1, 243, m1, len_m1, rounds);

    int hash_equal = 1;//memcmp(hash0, hash1, 243);

    if (hash_equal == 0) {
        // Check if messages are different
        if ((len_m0 != len_m1) || memcmp(m0, m1, len_m0)) {
            printf("Congratulations! Send your solution to troika-challenge@googlegroups.com!\n");
            printf("---\n");
            printf("[Competition] Break Collision %llu Rounds\n\n", rounds);
            printf("Submitters: Enter names here\n");
            printf("m0: ");
            print_trits_as_trytes(m0, len_m0);
            printf("\nm0_len: %llu\n", len_m0);
            printf("H(m0): ");
            print_trits_as_trytes(hash0, 243);
            printf("\nm1: ");
            print_trits_as_trytes(m1, len_m1);
            printf("\nm1_len: %llu\n", len_m1);
            printf("H(m1): ");
            print_trits_as_trytes(hash1, 243);
            printf("\nSummary: Describe briefly how you broke the challenge here.\n");
        } else {
            printf("Solution not valid! Messages are the same.\n");
        }
    } else {
        printf("Solution not valid! Hash is not the same\n");
    }
}

int main()
{
    // Example for verifying a preimage challenge for 4 rounds
    int rounds = 4;
    char *solution = "0AMWAKDAXC";
    int mlen = 30;  // Length is in trits
    Trit solution_trits[mlen];
    Trit image[243];

    // Convert to trits. You can also directly verify a message as trits.
    tryte_string_to_trits(image, preimage_challenges[rounds - 1], 81);
    tryte_string_to_trits(solution_trits, solution, mlen / 3);
    verify_preimage(solution_trits, mlen, image, rounds);

    // Example for verifiying a collision challenge
    rounds = 2;
    char *m0 = "AAAAAAAAAA";
    char *m1 = "AAAAAAAAAB";
    int len_m0 = 30;
    int len_m1 = 30;

    Trit m0_trits[len_m0];
    Trit m1_trits[len_m1];

    tryte_string_to_trits(m0_trits, m0, len_m0 / 3);
    tryte_string_to_trits(m1_trits, m1, len_m1 / 3);
    verify_collision(m0_trits, len_m0, m1_trits, len_m1, rounds);

    return 0;
}
