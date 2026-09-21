# =========================================
# Digital Content Protection & Authenticity
# Owner: Mohan Kumar J
# Project ID: PROJECT-001
# Watermark ID: WM-CODE-2026-B09BBEAD
# Created: 2026-08-18T05:49:39.780501+00:00
# =========================================
n = int(input("Enter number of elements: "))
arr = []
print("Enter elements:")
for i in range(n):
    arr.append(int(input()))
key = int(input("Enter key to search: "))
found = -1
for i in range(n):
    if arr[i] == key:
        found = i
        break
if found != -1:
    print("Key found at index", found)
else:
    print("Key not found")