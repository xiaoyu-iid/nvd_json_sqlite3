base_version = input("base version : ") 
prev_version = input("prev version : ") 
version_ints = base_version.split(".")
prev_version_ints = prev_version.split(".")

def traverse(partial_list, rest_value):
    print("new traversal!!!!!")
    result = []
    for i in partial_list:
        current=[]
        for j in rest_value[0]:
            current.append(str(i+"."+j))
        if len(rest_value) > 1:
            current = traverse(current, rest_value[1:])
        result += current
    return result

potential_versions = []

version_num = 0
prev_version_num = 0
length = len(version_ints)
if len(prev_version_ints) < length:
    prev_version_ints.append("0")

try:
    for index in range(length):
        potential_versions.append([])
        if index == 0:
            for num in range(int(prev_version_ints[index]),
                             int(version_ints[index]) + 1):
                potential_versions[index].append(str(num))
        else:
            larger = max(int(prev_version_ints[index]), int(version_ints[index]))
            for num in range(10*((larger // 10) + 1)):
                potential_versions[index].append(str(num))
except ValueError:
    pass

print("!!!!!!!!!!",potential_versions)
print(traverse(potential_versions[0], potential_versions[1:]))
