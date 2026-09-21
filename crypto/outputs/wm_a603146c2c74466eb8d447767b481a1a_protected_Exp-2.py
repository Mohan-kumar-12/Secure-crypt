# =========================================
# Digital Content Protection & Authenticity
# Owner: Mohan Kumar J
# Project ID: PROJECT-001
# Watermark ID: WM-CODE-2026-EFC8C60F
# Created: 2026-08-18T05:48:41.105189+00:00
# =========================================
def binary_search(arr,low,high,key):
    if low<=high:
        mid=(low+high)//2
        if arr[mid]==key:
            print("Key found at the index",mid)
        elif key<arr[mid]:
            binary_search(arr,low,mid-1,key)
        else:
            binary_search(arr, mid + 1, high, key)
    else:
            print("Key not found")
arr=list(map(int,input("Enter the sorted elements: ").split()))
key=int(input("Enter the key: "))
binary_search(arr,0,len(arr)-1,key)