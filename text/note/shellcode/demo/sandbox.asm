A = sys_number
# A == execve ? dead : next
# A == open ? dead : next
# A == read ? dead : next
# A == write ? dead : next
return ALLOW
dead:
return KILL
