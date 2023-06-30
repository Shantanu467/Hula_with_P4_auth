import os
import statistics
sum = 0

for i in range(10):
	os.system("python3 new_controller.py > times.txt")
	with open('times.txt', 'r') as f:
	    lines = f.read().splitlines()
	    last_line = lines[-1]
	    sum += float(last_line.split()[-1])
	print(f'{i+1} iterations done')

os.system('rm times.txt')
print(f'Average running time : {sum/10}')
