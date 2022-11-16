# gprs_decrypt

Didn't even notice some of the codes I was (re)writing had updates... or even existed.

I replaced DecryptGPRS with a slightly rewritten version of bnnm's LZGPRS decompressor,
making the code SIGNIFICANTLY smaller.

This variant of the LocoRoco GPRS decrypting program searches the entire file for a GPRS header and decrypts its contents.
It then skips over that section and decrypts other GPRS sections (it attempts to decrypt all encrypted sections within a file).

Non GPRS sections are added to the final file, essentially skipping them.

GPRS sections within GARC sections are skipped so as to preserve sizes and such,
meaning those will have to be decrypted after being extracted from their parent GARC section.

GPRS sections within GPRS sections aren't decrypted, so the resulting file will have to be decrypted a second time.
This seems to only be the case for LocoRoco 2 and Midnight Carnival, specifically the DATA.BIN files.
