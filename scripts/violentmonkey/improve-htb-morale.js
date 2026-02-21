// ==UserScript==
// @name        New script hackthebox.com
// @namespace   Violentmonkey Scripts
// @match       https://app.hackthebox.com/**
// @grant       none
// @version     1.0
// @author      -
// @description 30/01/2026, 12:09:25 am
// ==/UserScript==

((window, document) => {

  async function sleep(time) {
    return new Promise(resolve => window.setTimeout(resolve, time));
  }

  function improveMorale(levels, mapped, id, cb) {
    function updateLevelIfMatch(htmlElement) {
      const index = levels.findIndex(elem => elem === htmlElement.innerText.toLowerCase());
      if ( index < 0 ) {
        return;
      }
      htmlElement.innerText = mapped[index];
    }

    let retries = 10;
    const pollHtmlElements = window.setInterval(function() {
      if (retries < 1) {
        window.clearInterval(pollHtmlElements);
        return;
      }

      const htmlElementMaps = id.map(elem => Array.from(document.querySelectorAll(elem)));

      for (const htmlElement of htmlElementMaps) {
        if (htmlElement.length < 1) {
          retries = retries - 1
          return;
        }

        for (const elem of htmlElement) {
          updateLevelIfMatch(elem);
        }
      }

      window.clearInterval(pollHtmlElements);
      cb();

    }, 200);
  }

  function getMotivational() {
    const MOTIVATIONAL_MESSAGES = [
      "It does not matter how slowly you go as long as you do not stop.",
      "Success is not final, failure is not fatal: it is the courage to continue that counts.",
      "I have not failed. I've just found 10,000 ways that won't work.",
      "Our greatest glory is not in never falling, but in rising every time we fall.",
      "The only impossible journey is the one you never begin.",
      "It always seems impossible until it's done.",
      "Believe you can and you're halfway there.",
      "The secret of getting ahead is getting started.",
      "Act as if what you do makes a difference. It does.",
      "Let us not become weary in doing good, for at the proper time we will reap a harvest if we do not give up.",
      "Curiouser and curiouser!",
      "Why, sometimes I've believed as many as six impossible things before breakfast.",
      "In the middle of difficulty lies opportunity.",
      "Alice had begun to think that very few things indeed were really impossible.",
      "The man who moves a mountain begins by carrying away small stones.",
      "Read the directions and directly you will be directed in the right direction.",
      "Begin at the beginning and go on till you come to the end: then stop.",
      "Everything's got a moral, if only you can find it.",
      "Take care of the sense, and the sounds will take care of themselves.",
      "The mind is everything. What you think you become.",
      "We are what we repeatedly do. Excellence, then, is not an act, but a habit.",
      "Quality is not an act, it is a habit.",
      "To be yourself in a world that is constantly trying to make you something else is the greatest accomplishment.",
      "Knowing yourself is the beginning of all wisdom.",
      "It is our choices that show what we truly are, far more than our abilities.",
      "I am not crazy; my reality is just different from yours.",
      "We're all mad here.",
      "You're entirely bonkers. But I'll tell you a secret. All the best people are.",
      "A journey of a thousand miles begins with a single step.",
      "You miss 100% of the shots you don't take.",
      "Do what you can, with what you have, where you are.",
      "The only way to do great work is to love what you do.",
      "Stay hungry, stay foolish.",
      "You can never cross the ocean until you have the courage to lose sight of the shore.",
      "Do not go where the path may lead, go instead where there is no path and leave a trail.",
      "Two roads diverged in a wood, and I—I took the one less traveled by, and that has made all the difference.",
      "Everything you've ever wanted is on the other side of fear.",
      "Twenty years from now you will be more disappointed by the things you didn't do than by the ones you did do.",
      "What you get by achieving your goals is not as important as what you become by achieving your goals.",
      "Education is the most powerful weapon which you can use to change the world.",
      "The unexamined life is not worth living.",
      "The only true wisdom is in knowing you know nothing.",
      "Not all those who wander are lost.",
      "I give myself very good advice, but I very seldom follow it.",
      "How puzzling all these changes are! I'm never sure what I'm going to be, from one minute to another.",
      "The only thing we have to fear is fear itself.",
      "Courage is not the absence of fear, but rather the judgment that something else is more important than fear.",
      "The only limit to our realization of tomorrow is our doubts of today.",
      "That which does not kill us makes us stronger.",
      "He who has a why to live can bear almost any how.",
      "Winners don't make excuses when the other side plays the game.",
      "The lesson is: if you're gonna be a criminal, do your homework.",
      "No half measures.",
      "Perfection is not attainable, but if we chase perfection we can catch excellence.",
      "Clear eyes, full hearts, can't lose.",
      "You want it to be one way. But it's the other way.",
      "Just because you shot Jesse James, don't make you Jesse James.",
      "If you don't know where you are going, any road will get you there.",
      "Hard times create strong men, strong men create good times.",
      "What lies behind us and what lies before us are tiny matters compared to what lies within us.",
      "The future belongs to those who believe in the beauty of their dreams.",
      "Every passing minute is another chance to turn it all around.",
      "Nothing in this world that's worth having comes easy.",
      "Now, here, you see, it takes all the running you can do, to keep in the same place.",
      "It's a poor sort of memory that only works backwards.",
      "The time has come to talk of many things.",
      "Life is what happens when you're busy making other plans.",
      "I wish there was a way to know you were in the good old days before you actually left them.",
      "Your time is limited, don't waste it living someone else's life.",
      "If you want to go fast, go alone. If you want to go far, go together.",
      "I am the one who knocks.",
      "Say my name.",
      "I did it for me. I liked it. I was good at it.",
      "Tread lightly.",
      "We're done when I say we're done.",
      "This is the way.",
      "Chaos isn't a pit. Chaos is a ladder.",
      "A lion doesn't concern himself with the opinions of the sheep.",
      "It is not the critic who counts; the credit belongs to the man who is actually in the arena.",
      "Imagination is the only weapon in the war against reality.",
      "If I had a world of my own, everything would be nonsense.",
      "What is the use of a book without pictures or conversations?",
      "There's some good in this world, Mr. Frodo, and it's worth fighting for.",
      "Even the smallest person can change the course of the future.",
      "All we have to decide is what to do with the time that is given us.",
      "I can't carry it for you, but I can carry you.",
      "So do all who live to see such times, but that is not for them to decide.",
      "You either die a hero or live long enough to see yourself become the villain.",
      "What is grief, if not love persevering?",
      "That's what I do: I drink and I know things.",
      "Cool. Cool cool cool.",
      "Legen—wait for it—dary!",
      "I'm not superstitious, but I am a little stitious.",
      "Be the change that you wish to see in the world.",
      "It's no use going back to yesterday, because I was a different person then.",
      "I knew who I was this morning, but I've changed a few times since then.",
      "Who in the world am I? Ah, that's the great puzzle.",
      "Darkness cannot drive out darkness: only light can do that.",
      "The best time to plant a tree was 20 years ago. The second best time is now.",
      "Make it simple, but significant.",

      // Murder Drones

      "And they said pirating all that anime was useless",
      "I'm done dealing with everything alone. We move forward together, or not at all",
      "You CHOSE to leave me for dead instead of just freaking BELIEVING IN ME!",
      "I'm sorry for being vulnerable for five seconds, okay?!",
      "Hey... thanks for, like... everything",
      "It doesn't work YET. Who said it doesn't work?! Maybe it does!",
      "Neat. Therapy's fun",
      "And maybe I don't actually hate it here... as much",
      "I guess I just wanna be useful. I was given a job, and I always wanna try my best",
      "You sure are rebellious. It's kind of exciting",
      "I'd join you if the sun didn't kill me. Hope you're having important character growth or something, though!",
      "And yet, I still feel nothing",
      "You've gotta lot of guts for a barely sentient toaster",
    ]

    return MOTIVATIONAL_MESSAGES[Math.floor(Math.random() * MOTIVATIONAL_MESSAGES.length)]
  }


  async function updateQuote() {
    const el = document.getElementById('motivational');
    if (el !== null) {
      const nextQuote = getMotivational();

      el.innerText = "";
      for (word of nextQuote.split(" ")) {
        el.innerText = el.innerText + ` ${word}`;
        await sleep(Math.random() * 200);
      }
    }
  }

  function onPageUpdate() {
    // machine difficulty
    improveMorale(
      ["easy", "medium", "hard", "insane"],
      ["Intermediate", "Advanced", "Extreme", "Frontier"],
      ['.avatar-icon-name-details ul li'],
      () => {

        window.setTimeout(() => {
          document.querySelector('ul.common-bloods-list').remove();
        }, 4000);


        window.setTimeout(() => {
          let motivationalMessage = `<li class="htb-codeblock-md htb-d-flex htb-justify-center htb-align-center avatar-icon-name-details__badge-list-item monkey__motivational-message">
<span aria-hidden="true" class="htb-mx-8 htb-text-secondary avatar-icon-name-details__badge-list-item-divider avatar-icon-name-details__badge-list-item-divider--responsive">·</span>
<span id="motivational" class="htb-font-medium htb-text-link-hover" style="cursor:pointer;"></span>
</li>`;

          if (document.querySelector('.monkey__motivational-message') == null) {
            document.querySelector('.profile-page-base-header ul').insertAdjacentHTML('beforeend', motivationalMessage);

            // Click to change quote
            document.getElementById('motivational').addEventListener('click', () => {
              updateQuote()
            });
          }

          if (document.getElementById('motivational').innerText === "") {
            updateQuote();
          }

          // reduce user telemetry noise for now. No need to compare yourself to others
          document.querySelector('.profile-page-base-header__extra-info-statistics').remove();

        }, 500);
      }
    );

    // profile "Noob"
    improveMorale(
      ["noob", "sriptkiddie", "hacker"],
      ["Cadet", "Private", "Sergeant"],
      ['div.htb-mt-auto:nth-child(2) > div:nth-child(2) > h3:nth-child(2)', '.htb-status--secondary'],
      () => {
        document.querySelector('div.htb-mt-auto:nth-child(2) > img:nth-child(1)').src = '/images/badges/ic-rank-elitehacker.svg'

        setTimeout(() => {
          document.querySelector('div.htb-mt-auto:nth-child(2) > img:nth-child(1)').style['margin-top'] = '57px';
        }, 100)

        document.querySelector('div.htb-mt-auto:nth-child(2) > div:nth-child(2) > span:nth-child(1)').innerText = getMotivational();
        document.querySelector('div.common-stats-card__root:nth-child(1) > section:nth-child(2) > dl:nth-child(1) > div:nth-child(1)').remove();
        document.querySelector('.progress-container').remove();
      }
    )
  }

  window.setTimeout(onPageUpdate, 2000);

  let lastUrl = location.href;
  let isUpdatingPage = false;

  const observer = new MutationObserver(() => {
    if (isUpdatingPage) return;
    if (window.location.href === lastUrl) return;

    isUpdatingPage = true;
    lastUrl = location.href;
    window.setTimeout(() => {
      try {
        onPageUpdate();
      } finally {
        isUpdatingPage = false;
      }
    }, 500);
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

})(window, document);
