from pytoniq_core import mnemonic

# Membuat frase mnemonic 24 kata
mnemonic_phrase = mnemonic.generate_mnemonic(num_words=24)
print("Mnemonic Phrase:", mnemonic_phrase)
