(function () {
    const cards = document.querySelectorAll('[data-circulating-supply]');
    if (!cards.length) return;

    fetch('/api/circulating_supply')
        .then(function (response) {
            if (!response.ok) throw new Error('Supply unavailable');
            return response.json();
        })
        .then(function (supply) {
            if (typeof supply !== 'number' || !Number.isFinite(supply) || supply < 0) {
                throw new Error('Supply unavailable');
            }
            cards.forEach(function (card) {
                let value = card.querySelector('.value');
                if (!value) {
                    value = document.createElement('span');
                    value.className = 'value';
                    card.appendChild(value);
                }
                value.title = supply.toLocaleString('en-US', {maximumFractionDigits: 0}) + ' BDX';
                const billions = supply / 1e9;
                value.textContent = billions.toLocaleString('en-US', {
                    maximumFractionDigits: billions >= 100 ? 0 : billions >= 10 ? 1 : 2
                });
                const unit = document.createElement('span');
                unit.className = 'unit';
                unit.textContent = 'B BDX';
                value.appendChild(unit);
                const note = card.querySelector('.note');
                if (note) note.remove();
            });
        })
        .catch(function () {
            // Keep any cached or on-chain value when the remote service is down.
            cards.forEach(function (card) {
                const note = card.querySelector('.note');
                if (note) note.textContent = 'temporarily unavailable';
            });
        });
})();
