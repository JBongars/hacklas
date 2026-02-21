# Notes to Self: When You're Stuck and Frustrated

---

## The discomfort is the learning

A Harvard study (Deslauriers et al., 2019) found that students doing messy, uncomfortable active learning scored higher than those in polished lectures — even though the lecture group _felt_ like they learned more. Actual learning and feeling of learning were strongly anticorrelated.

> "Learning has to feel uncomfortable, you have to feel like you are breaking a frontier. Because in a way you are. It doesn't feel natural until one day it does."

---

## The hardest bugs are almost always the stupidest bugs

Before you spiral into kernel exploits and exotic chains, go back to the surface.

> "I found when I was a SWE, there were so many times where I was faced with such an impossible bug that turned out to just be a spelling mistake or a configuration thing or some minor misstep which caused everything to lock up. What you don't see is usually right in front of you."

> "The crazy thing is at the time you think you scanned all the low hanging fruits so now you are looking at kernel exploits or trying to break tar files. But actually you just needed to check ownership with `find / -uid $(id -u)` or `find / -suid -executable` or something."

Re-read your scan output slowly. You probably scrolled past something.

---

## Exploitation vs. enumeration

Exploitation has a tight feedback loop. It works or it doesn't. "Try harder" applies here.

Enumeration is different. You can't try harder at seeing something you don't know to look for.

> "Enumeration is more art than science. There is a lot of practice you need in order to be half decent. Even with 12 years experience, 6 months in, I still miss a lot of things. But I think you can get better."

Every box adds to your mental model. Give yourself grace.

---

## Walkthroughs are not cheating

> "I think the key is not to ask yourself 'what is the solution' but more like 'If I had 20 years of experience, how would I look at this to find the solution.'"

But the type of walkthrough matters:

> "The HTB walkthroughs... they feel like they want you to believe the creator is some kind of wizard that are able to exploit with hopes and dreams on their first attempt but like there is a noob and an expert way to explore dead ends. But if they don't show you the dead ends or the tangents then it's just as bad as not doing anything. Those are the kind of walkthroughs that keep you hooked. Because it's not giving you the whole story."

> "I could look at a Rubik's cube and give you the exact sequence of moves to get it to a solved state. But if I never showed you how those moves work. If I never explain combinatorics and permutations and parity bits, you will never be able to solve the Rubik's cube on your own even though it FEELS like you are."

IppSec shows the thinking. The dead ends. The methodology. That's apprenticeship, not a crutch.

The goal isn't to force yourself to never use walkthroughs:

> "I don't think the correct model is to force yourself not to use a walkthrough, I think if you are doing this correctly, you will forget to use one at all and find that there is nothing you got stuck on."

---

## The bootstrap principle

> "I can't just dump you in an environment where nothing is working. As a senior, I used to onboard juniors by basically setting up their environment for them... So then they feel 'safe' to explore around. They know that if they make a mistake or something doesn't behave the way they want it to, they can always revert and try again."

Your baseline is your methodology, your notes, your enumeration checklist. Every box you do makes the bootstrap stronger.

---

## The gap is not as big as it feels

> "You feel like a speck of dirt in front of a literal demigod. Like so insignificant. You feel like the gap is just too extreme."

It's not. It's mostly exposure time. Every senior was once the person staring at a missing semicolon for four hours.

> "That's why the best way is to let people rubber duck with you and just nudge them in the right direction or just limit the surface of attack."

Be that person for yourself. Rubber duck with your notes. Narrow the surface. Re-enumerate.

---

## When "try harder" actually applies (and when it doesn't)

> "If you exhausted all your possibilities, it means you are missing a piece of information. A tool in your toolbox or kink in your methodology."

> "If I give a complete beginner a printer and I ask them to find root so they can disable the low ink warning... if that person doesn't have enough to even get started, I think it's a bit unfair to say 'try harder' or 'git good.'"

- You found the attack surface but aren't digging deep enough → **try harder**
- You don't know what you don't know → **you need information, not grit**
- You've been staring for an hour → **step away, come back, re-enumerate from scratch**
- You're spiraling into complex chains → **go back to basics, check the simple stuff again**

> "You have to afford yourself the grace of using a walkthrough cause that is SO much more productive than just 'trying harder'. ESPECIALLY if you are going at this alone."

---

## Now close this document and go pop a box.

**Resources:**

- TJ Null's list: [NetSecFocus Trophy Room](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit)
- TJ Null's prep guide: [netsecfocus.com](https://www.netsecfocus.com/oscp/2021/05/06/The_Journey_to_Try_Harder-_TJnull-s_Preparation_Guide_for_PEN-200_PWK_OSCP_2.0.html)
- IppSec's YouTube: [youtube.com/@ippsec](https://www.youtube.com/@ippsec)
