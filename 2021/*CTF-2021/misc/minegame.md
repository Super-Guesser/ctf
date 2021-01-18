## Challenge Description

`If you love reverse, you can try it, otherwise, you must finish it as quickly as possible.`

[attachment](https://adworld.xctf.org.cn/media/uploads/task/f9fd04cdbed4469d856b92b9a648041a.zip)

## Solution

After installing hefty MATLAB Runtime, running the executable we are being presented with the Minesweeper game:

![](https://i.imgur.com/WIOyH07.png)

Real challenge is to solve it in less than a minute. After a couple of tries, it was clear that this was an impossible task to do without any cheating.
Thus, tried to utilize [Cheat Engine](https://www.cheatengine.org/) to "slow" it down, but failed. Nevertheless, an interesting thing happened during tests.
After suspending the process at start and resuming it later on, program exited instantly. Thus, it came to mind that system time is being used to check whether the
game should exit due to expiration period. So, final solution that worked was to suspend the game at start, turn back time to one hour before and actually solve the
given minesweeper challenge without any time pressure.

## Flag

`*CTF{Y0u_41e-gLeat_6Oy3!}`
