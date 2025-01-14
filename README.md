# delphi-crypt-finder
The purpose of this script is identifying and labeling a string encryption algorithm commonly used by brazilian banking malware written in Delphi (you can read more about the algo [here](https://www.welivesecurity.com/2019/10/03/casbaneiro-trojan-dangerous-cooking/), courtesy of ESET).

It works by identifying a sequence of `movzx`, `xor`, `mov`and `cmp` instructions that are responsible for doing the `x = c ^ key[i % len(key)]` operation for each encrypted byte by their opcodes.

To be more assertive, the code checks that said instructions operate on the same register, without specifying which one. If it finds one or more functions that match this pattern, the scripts writes their addresses to output and renames them as `mw_string_decrypt`.

# DISCLAIMERS

**THIS SCRIPT DOES NOT IDENTIFY A SAMPLE AS MALICIOUS**. This string encryption algorithm is simple and common enough that it is present in harmless Delphi applications as well. The purpose of this script is simply speeding up the reversing of malware families that use it.

This is not infallible. I have tested it in random samples from Ousaban, Grandoreiro and Chavecloak and had it work fine. However, it failed on Casbaneiro samples that do use this same algorithm. This is because the instructions don't always match my pattern and I'm uncomfortable with making this match on less opcodes due to potential of false positives. So **if this doesn't match any functions, don't assume the algorithm isn't used**. It might just have been compiled to a slightly different format.
