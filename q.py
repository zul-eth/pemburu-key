from itertools import islice, product

printed_results = set()

for private in islice(product('0123456789abcdef', repeat=3), 0, None):
    pr = ''.join(private)
    if pr[::-1] not in printed_results:  # Check if the reverse is not printed
        print(pr)
        printed_results.add(pr)
