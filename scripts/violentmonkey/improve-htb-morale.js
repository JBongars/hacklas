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
  const improveMorale = (levels, mapped, id, cb) => {
    function updateDifficulty(level) {
      return mapped[levels.findIndex(elem => elem === level.toLowerCase())];
    }

    let retries = 50;
    const int = window.setInterval(function() {
      if (retries < 1) {
        clearInterval(int);
        return;
      }

      const elems = id.map(elem => document.querySelector(elem));
      console.log(elems);

      for (const elem of elems) {
        if (typeof elem === 'null' || elem === null ) {
          retries = retries - 1;
          return;
        }
        const nextValue = updateDifficulty(elem.innerText);
        elem.innerText = nextValue;
      }

      clearInterval(int);
      cb();

    }, 200);
  }

  // machine difficulty
  if (window.location.pathname.includes("/machines")) {
    improveMorale(
      ["easy", "medium", "hard", "insane"],
      ["Intermediate", "Advanced", "Extreme", "Frontier"],
      ['li.htb-codeblock-md:nth-child(1) > span:nth-child(1)'],
      () => null
    );
  }

  // profile "Noob"
  if (window.location.pathname.includes("/users")) {
    improveMorale(
      ["noob", "sriptkiddie", "hacker"],
      ["OSCP Candidate", "OSCP In Progress", "Penetration Tester"],
      ['div.htb-mt-auto:nth-child(2) > div:nth-child(2) > h3:nth-child(2)', '.htb-status--secondary'],
      () => {
        document.querySelector('div.htb-mt-auto:nth-child(2) > img:nth-child(1)').src = '/images/badges/ic-rank-elitehacker.svg'
        document.querySelector('div.htb-mt-auto:nth-child(2) > div:nth-child(2) > span:nth-child(1)').innerText = "Get Fucked HTB!"
        document.querySelector('div.common-stats-card__root:nth-child(1) > section:nth-child(2) > dl:nth-child(1) > div:nth-child(1)').remove()
      }
    )
  }

})(window, document);
