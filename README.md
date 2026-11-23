# 401-to-200-OK

Run:
```
> httpx -l alive.txt -mc 400,401,403 -o 40X.txt

> python3 check_401_to_200.py -f 40X.txt
```
