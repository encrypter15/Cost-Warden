document.addEventListener('DOMContentLoaded', () => {
    const ctx = document.getElementById('vulnChart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['Jan', 'Feb', 'Mar', 'Apr'],
            datasets: [
                {
                    label: 'Vulnerabilities',
                    data: [10, 20, 15, 25],
                    borderColor: 'red',
                    fill: false
                },
                {
                    label: 'Anomalies',
                    data: [1, 3, 0, 2],
                    borderColor: 'blue',
                    fill: false
                }
            ]
        }
    });
});
