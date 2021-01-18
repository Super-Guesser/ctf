## Challenge Description

`the flag format is flag{...}`

![](https://i.imgur.com/m5VSmBV.jpg)

## Solution

By repeated usage of [Gaps](https://github.com/nemanja-m/gaps), we were able to get partial solves of the puzzle:

```
gaps --image=puzzle.png --generations=100 --population=600
```

After failing with different approaches to **finish** the puzzle, final solution involved copy-pasting of recognized flag parts (from partial solves) into the Googled
original image which was used to write the flag to:

![](https://i.imgur.com/XUBK1O1.jpg)

## Flag

`flag{you_can_never_finish_the}`
