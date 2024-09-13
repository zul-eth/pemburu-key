def find_combinations(target):
    stack = [(0, 0, [])]   (current_sum, start, path)
    while stack:
        current_sum, start, path = stack.pop()
        if current_sum == target:
            print(' + '.join(map(str, path)), '=', target)
        elif current_sum < target:
            for i in range(start, 31):
                stack.append((current_sum + i, i, path + [i]))   

def main():
    target_sum = 65
    print("hasil:")
    find_combinations(target_sum)

if __name__ == "__main__":
    main()
