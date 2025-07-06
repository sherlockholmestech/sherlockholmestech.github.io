---
title: GreyCTF 2025 Qualifiers
published: 2025-07-06
description: 'The ones that I bother to write after the ctf'
image: ''
tags: ["Ctf", "Osint", "Crypto"]
category: 'CTF Writeups'
draft: false 
lang: ''
---
# Preamble

GreyCTF 2025 was quite the eye-opener, as the first CTF that I have _properly_ particiapted in. Here are the writeups for the challs that I bothered to write for, do enjoy.

# Writeups

## Ezpz - Tung Tung Tung Sahur

### Challenge Description
> New to the world of brainrot? Not sure what names to pick from? We've got you covered with a list of our faves:
> 
> Tralalero Tralala
> 
> Chef Crabracadabra
> 
> Boneca Ambalabu
> 
> Tung Tung Tung Tung Tung Tung Tung Tung Tung Sahur

Challenge script tung_tung_tung_sahur.py:
```python=
from Crypto.Util.number import getPrime, bytes_to_long

flag = "grey{flag_here}"

e = 3
p, q = getPrime(512), getPrime(512)
N = p * q 
m = bytes_to_long(flag.encode())
C = pow(m,e)

assert C < N 
while (C < N):
    C *= 2
    print("Tung!")

# now C >= N

while (C >= N):
    C -= N
    print("Sahur!")


print(f"{e = }")
print(f"{N = }")
print(f"{C = }")
```

### Thinking Process
Absolutely hilarious (not) name aside, this challenge was one of the quickest to be solved in our team (other than Sanity Check, of course). A quick glance at the python code immediately jumped at me that this was some sort of easy crypto challenge.

```python=
assert C < N 
while (C < N):
    C *= 2
    print("Tung!")

# now C >= N

while (C >= N):
    C -= N
    print("Sahur!")
```
From these lines in the challenge script, we can see that $C$ is multiplied by $2^x$, where $x$ is the number of lines of "Tung!" printed, which from the output given is 164.  Also, before printing "Sahur!", we can see that the value of $C$ is subtracted by $N$.

In order to recover the original value of $C$, I began by adding back the value of $N$, and dividng $C$ by $2^{164}$.

```python=
C = 49352042282005059128581014505726171900605591297613623345867441621895112187636996726631442703018174634451487011943207283077132380966236199654225908444639768747819586037837300977718224328851698492514071424157020166404634418443047079321427635477610768472595631700807761956649004094995037741924081602353532946351
C_atlered = C + 140435453730354645791411355194663476189925572822633969369789174462118371271596760636019139860253031574578527741964265651042308868891445943157297334529542262978581980510561588647737777257782808189452048059686839526183098369088517967034275028064545393619471943508597642789736561111876518966375338087811587061841
C_original = C_atlered / (2 ** 164)
print(f"{C_original = }")
```
Now with $C_{original}$ recovered, we can now start recovering the value of $m$ in bytes. In the challenge script, it is seen that:
```python=
e = 3
p, q = getPrime(512), getPrime(512)
N = p * q 
m = bytes_to_long(flag.encode())
C = pow(m,e)
```
We can therefore conclude that $C_{original} = m^3$, hence $m = \sqrt[3]{C_{original}}$.
```python=
m = C_original ** (1/3)
print(f"{m = }")
flag = long_to_bytes(int(m)).decode()
print(f"{flag = }")
```
### Solution
Therefore, we end up with this python script as the solution:
```python=
from Crypto.Util.number import long_to_bytes

C = 49352042282005059128581014505726171900605591297613623345867441621895112187636996726631442703018174634451487011943207283077132380966236199654225908444639768747819586037837300977718224328851698492514071424157020166404634418443047079321427635477610768472595631700807761956649004094995037741924081602353532946351
C_atlered = C + 140435453730354645791411355194663476189925572822633969369789174462118371271596760636019139860253031574578527741964265651042308868891445943157297334529542262978581980510561588647737777257782808189452048059686839526183098369088517967034275028064545393619471943508597642789736561111876518966375338087811587061841
C_original = C_atlered / (2 ** 164)
print(f"{C_original = }")
m = C_original ** (1/3)
print(f"{m = }")
flag = long_to_bytes(int(m)).decode()
print(f"{flag = }")
```

But when running this script, we actually get this output:

![image](https://hackmd.io/_uploads/S132a3tzeg.png)


What is happening?

Apparently, python's floating point maths lose precision at such large numbers. In order to ensure precision, I had to convert everything to rust:
```rust=
use num_bigint::BigUint;
use num_traits::Pow;
use std::str;

fn main() {
    let c = BigUint::parse_bytes(b"49352042282005059128581014505726171900605591297613623345867441621895112187636996726631442703018174634451487011943207283077132380966236199654225908444639768747819586037837300977718224328851698492514071424157020166404634418443047079321427635477610768472595631700807761956649004094995037741924081602353532946351", 10).unwrap();
    let n = BigUint::parse_bytes(b"140435453730354645791411355194663476189925572822633969369789174462118371271596760636019139860253031574578527741964265651042308868891445943157297334529542262978581980510561588647737777257782808189452048059686839526183098369088517967034275028064545393619471943508597642789736561111876518966375338087811587061841", 10).unwrap();
    let c_altered = &c + &n;
    let divisor = BigUint::from(2u32).pow(164u32);
    let c_original = &c_altered / divisor;
    println!("C_original = {}", c_original);
    let m = integer_cube_root(&c_original);
    println!("m = {}", m);
    let flag_bytes = m.to_bytes_be();
    let flag = str::from_utf8(&flag_bytes).unwrap();
    println!("flag = {}", flag);
}

fn integer_cube_root(n: &BigUint) -> BigUint {
    if *n == BigUint::from(0u32) {
        return BigUint::from(0u32);
    }
    
    let mut x = n.clone();
    let mut y = (&x + 2u32) / 3u32;
    
    while y < x {
        x = y.clone();
        y = (2u32 * &x + n / (&x * &x)) / 3u32;
    }
    
    x
}
```
This then finally printed out the correct flag.
![image](https://hackmd.io/_uploads/SkVYpnKfgl.png)

Flag: `grey{tUn9_t00nG_t0ONg_x7_th3n_s4hUr}`

## Osint - Beside the Banana Tree

### Challenge Description
> I saw a church in the distance while travelling. Can you tell me where it is?
> 
> The flag consists of latitude and longitude coordinates of the location where the photo was taken, rounded to three decimal places, and the name of the church in the distance in lowercase (according to google maps, omitting any potential spaces, punctuation and diacritics).
> 
> Regarding flag format, consider this example for Notre Dame de Paris: grey{N48-853_E2-349_notredamecathedralofparis}

![image](https://i.imgur.com/J62xWwt.jpeg)

### Thinking Process
After first seeing the image, my mind immediately thought that this photo was taken somewhere in rural Asia (I don't know why, it just seemed like so). Upon closer inspection, we can acually see a milestone along the side of the road:

![bythebananatree copy](https://hackmd.io/_uploads/BJ3mY1cfgx.png)

We can see that the milestone references 2 roads: ĐT.317G as well as QL.32. With a simple Google search, I found that ĐT.317G refers to a provicial road in Vietnam, and QL.32 refers to a national highway in Vietnam. However, after this, I was slightly stuck, as ĐT.317G didn't exist on Google Maps. I figured it must be related in *some way* to ĐT.317, so I limited myself to this search area:

![image](https://hackmd.io/_uploads/rJqgqycfeg.png)

After tediously scanning the outskirts of ĐT.317 and QL.32, I finally came across this church, which seemed to have the same design as the one in the photo:

![image](https://hackmd.io/_uploads/By2O915Mxe.png)

From there, I tried to figure out the coordinates at which the photo was taken. After *countably infinite* attempts, I finally located this cute little junction that seemed to match up to the features of the photo: water, and a building after the junction.

![image](https://hackmd.io/_uploads/HJ0djy9flx.png)

### Solution

With the above information, I confidently entered the flag `grey{N21-153_E105-274_nhathophulao}` into CTFd.

But wait!

It was incorrect?

How could that be?

Thinking that it could be a off-by-one error in my latitude and longitude positions, I tried multiple times altering the 3rd decimal place, but to no avail. This problem probably accounted for 50% of all my team's failed submissions.

Well, it turned out that some guy on Google maps had uploaded a wrong photo of the church. After searching for a while, I then came across the correct church:

![image](https://hackmd.io/_uploads/HyoF3y9Gll.png)

Moral of the story: Don't trust community photographs from Google Maps.

Flag: `grey{N21-153_E105-274_nhathothanhlam}`

## Osint - A Walk in the Park

### Challenge Description

> Warm up your OSINT skills with this challenge!
> 
> You are given an image of a sign in the park.
> 
> Submit the text on the sign as the flag in lowercase, converting all new lines and spaces to underscores.
> 
> For example, if the sign looks like this:
> 
> 
> ABC PARK
> 
> 123 Main St. 
> 
> Singapore
> 
> Then, submit the flag as grey{abc_park_123_main_st_singapore}.

![a_walk_in_the_park](https://hackmd.io/_uploads/SJJzT15Mex.jpg)

### Thinking Process

The moment I saw the National Parks (NParks) sign in the corner, I immediately knew I had to solve this challenge, being a local Singapore resident.  If I could find the location of a church in the world, I could definitely find the location of a park in Singapore, right? At a glance, the place looked quite familiar to me, but afer a second of critical thinking I realised that all parks in Singapore pretty much looked the same, and I could not soley rely on contextual knowledge to solve this.

As any self-respecting osint solver would do, I plugged the image into Google Image Reverse Search to see if I could find any results. All I got were generic eBay metal signs up for sale.

With that out of the way, I then headed onto the NParks website to check the list of parks in Singapore. However, there was a *slight* issue:

![image](https://hackmd.io/_uploads/Sk-kgx9zxe.png)

It would be rather *infeasable* for me to check all the parks on the NParks website. After using random sampling to check the signs of a few parks, I realised that doing this would lead me to nowhere. So I put this to rest for the night, planning to pick this up the next day.

The next day, I awoken to a ping in my team chat, telling me to check the exif data of the image.

![image](https://hackmd.io/_uploads/S1argl5Glg.png)

Initially I had dismissed this clue as a dead end, having done a quick google search yielding no results.

However his ping *inspired* me do more digging. Having partially done Red Flag Recon *(looking at you ducati777)*, and knowing how much the GreyCTF team loves Instagram, I decided that it wouldn't hurt to check Instagram for this username.

And lo and behold, there was a public Instagram account under that name.

![image](https://hackmd.io/_uploads/HyVtZlqzle.png)

Looking through his stories, I noticed this incomplete address for a McDonalds order:

![image](https://hackmd.io/_uploads/BJgTbgcGxe.png)

This location led me to a park nearby called one-north Park: Biopolis.

![image](https://i.imgur.com/NN1WVkd.jpeg)

However, upon closer inspection, I realised that this park did not contain the same sign as seen in the challenge photo.

After taking a detour to doomscroll Instagram for a while, I viewed the stories again to notice these posts:

![image](https://hackmd.io/_uploads/Syp5fgcGxl.png)

![image](https://hackmd.io/_uploads/Byy2Me5zxl.png)

Knowing a classmate who is into running and uses a Garmin watch, I hypothesised that he may be into running, and uses a smartwatch to track his runs. On instinct, I immediately checked Strava, a popular app to track runs, for his account.

![image](https://hackmd.io/_uploads/ByHB7l9zge.png)

From the exif data, we know that the photo was taken on May 21st, and I found this walk on May 21st.  This means that he must have taken that photo while on this walk.  After a bit of searching along the route, I finally found this park:

![image](https://hackmd.io/_uploads/rJ8nQx5feg.png)

### Solution
Combining the above information, we can thereby conclude that the flag is `grey{interim_park_upper_serangoon_road}`. Luckily for us, it was the correct flag, and we did not exhaust our 3 tries.

This challenge almost drove me crazy before I realised the importance of the exif data.

Flag: `grey{interim_park_upper_serangoon_road}`