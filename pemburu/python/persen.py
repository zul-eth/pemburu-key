from decimal import Decimal

def cv_persen(inp):
    nilai = Decimal('340282366920938463463374607431768211455')
    persentase = Decimal(inp) / Decimal('100')
    hasil = nilai * persentase
    hasil_bulat = hex(int(hasil))[2:]
    print("hasil  :", hasil_bulat)

for i in range(1, 10001):
    persen_str = '{:.4f}'.format(i / 100)
    print(persen_str, " %")
    cv_persen(persen_str)
