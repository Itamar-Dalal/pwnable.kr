# CMD3

The script gives us rbash (restricted bash) but with a small list of available characters:

```
#  comment
$  variables
%  jobs
() parenthesis 
+ 
, 
- 
. 
/ 
: 
; 
<> 
=  
? 
@ 
[] 
\  
^ 
_ 
{} 
~
```

# Ideas

1. Reverse the python `random.choice` function. using the generated filename maybe we can deduce thing about the password (bye reversing the state).
2. Try to get characters using bash string indexing and build the command


# Experimentation

Expressions we can make:

`$$` - current pid
`$(( $$ / $$ ))` - 1
`$(( $$ - $$ ))` - 0
`????` - get name with matching number of chars (only first) (e.g. if we enter `????` we'll get `jail`)
`$_` - get string "/bin/rbash" - characters "binrash"

`${_:$(($$/$$)):$(($$/$$))}` - get "b" 

`$@` - postional parameters, equivalent to "$1" "$2" ...
`$#` - number of position arguments
`$?` - exit status
`$-` - gives the string "hrBs"
`{a..z}` - all characters in the range



`???????;$_` - flagbox

`.????????????;${_:$((($$+$$+$$+$$+$$+$$)/$$)):$((($$+$$+$$+$$+$$+$$+$$+$$)/$$))}` - history

`????/???;${_:$((($$+$$+$$+$$+$$)/$$)):$((($$+$$+$$)/$$))}` - cat
`????/??;${_:$((($$+$$+$$+$$+$$)/$$)):$((($$+$$)/$$))}` - ls


`????/??;__=${_:$((($$+$$+$$+$$+$$)/$$)):$((($$+$$)/$$))};___=$($__);???????;_____=${___:7:1}`


`?????.??;__=${_:3:1};????.??;__=$__${_:0:1};.????_???????;__=$__${_:4:1};???;__=$__${_:1:1}` - saves echo to $__
`????/??;____=${_:5:2};___=$($__);???????;_____=${___:7:1}` - saves ` ` (space) to $_____
`$-;___=${_:2:1}` - saves B to $___
`???????;____=${_:2:1}` - saves a to $____
`$__$_____{$___..$____}` - echo {B..a}



`.????_???????;__=${_:11:1};?????.??;__=$__${_:3:1};.????_???????;__=$__${_:2:1};????.??;__=$__${_:2:1};` - saves read to $__
`$__$___ ____;$____ `

`.????_???????;___=${_:9:1};????.??;___=$___${_:1:1};????.??;___=$___${_:5:1}` - saves tmp to $___
`????/??;____=${_:5:2};____=$($__);???????;_____=${____:7:1}` - saves ` ` (space) to $_____
`$(????/???;${_:5:3)}$_____/$___/__)`
## Builtins

- `.` `source`
- `echo`
- `eval` !!!
