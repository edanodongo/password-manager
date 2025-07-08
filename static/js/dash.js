// dash.js
console.log("dash.js loaded");


document.addEventListener("DOMContentLoaded", () => {
    const dataSource = document.getElementById('chart-data');

    const companyNatureLabels = JSON.parse(dataSource.dataset.natureLabels);
    const companyNatureData = JSON.parse(dataSource.dataset.natureData);
    const businessModelLabels = JSON.parse(dataSource.dataset.businessModelLabels);
    const businessModelData = JSON.parse(dataSource.dataset.businessModelData);
    const stageLabels = JSON.parse(dataSource.dataset.stageLabels);
    const stageData = JSON.parse(dataSource.dataset.stageData);
    const yearLabels = JSON.parse(dataSource.dataset.yearLabels);
    const yearData = JSON.parse(dataSource.dataset.yearData);
    const monthLabels = JSON.parse(dataSource.dataset.monthLabels);
    const allYearsData = JSON.parse(dataSource.dataset.allYearsData);
    const availableYears = JSON.parse(dataSource.dataset.availableYears);

    const animationOptions = {
        responsive: true,
        animation: {
            duration: 1000,
            easing: 'easeOutBounce'
        },
        plugins: {
            tooltip: {
                enabled: true,
                callbacks: {
                    label: function (context) {
                        return `${context.label}: ${context.raw}`;
                    }
                }
            },
            legend: {
                position: 'bottom'
            }
        }
    };

    new Chart(document.getElementById('companyNatureChart'), {
        type: 'pie',
        data: {
            labels: companyNatureLabels,
            datasets: [{
                data: companyNatureData,
                backgroundColor: ['#4e79a7', '#f28e2c', '#e15759', '#76b7b2', '#59a14f']
            }]
        },
        options: animationOptions
    });

    new Chart(document.getElementById('businessModelChart'), {
        type: 'bar',
        data: {
            labels: businessModelLabels,
            datasets: [{
                label: 'Count',
                data: businessModelData,
                backgroundColor: '#f28e2c'
            }]
        },
        options: {
            ...animationOptions,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    new Chart(document.getElementById('stageChart'), {
        type: 'doughnut',
        data: {
            labels: stageLabels,
            datasets: [{
                data: stageData,
                backgroundColor: ['#edc949', '#af7aa1', '#ff9da7', '#9c755f', '#bab0ab']
            }]
        },
        options: animationOptions
    });

    new Chart(document.getElementById('establishmentYearChart'), {
        type: 'line',
        data: {
            labels: yearLabels,
            datasets: [{
                label: 'Companies Established',
                data: yearData,
                fill: false,
                borderColor: 'rgb(75, 192, 192)',
                tension: 0.3
            }]
        },
        options: animationOptions
    });

    // Year Comparison Chart
    const comparisonChartCtx = document.getElementById('comparisonChart').getContext('2d');
    const comparisonChart = new Chart(comparisonChartCtx, {
        type: 'bar',
        data: {
            labels: monthLabels,
            datasets: []
        },
        options: {
            ...animationOptions,
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            onClick: (e, activeEls) => {
                if (activeEls.length > 0) {
                    const active = activeEls[0];
                    const year = comparisonChart.data.datasets[active.datasetIndex].label;
                    const month = comparisonChart.data.labels[active.index];
                    alert(`Drilling into ${month} ${year}`);
                }
            }
        }
    });

    const getColorForYear = (index) => {
        const palette = ['#4e79a7', '#f28e2c', '#e15759', '#76b7b2', '#59a14f', '#edc949', '#af7aa1'];
        return palette[index % palette.length];
    };

    const yearSelect = document.getElementById('yearSelect');
    yearSelect.addEventListener('change', () => {
        const selectedYears = Array.from(yearSelect.selectedOptions).map(opt => opt.value);
        comparisonChart.data.datasets = selectedYears.map((year, index) => ({
            label: year,
            data: allYearsData[year],
            backgroundColor: getColorForYear(index)
        }));
        comparisonChart.update();
    });

    yearSelect.dispatchEvent(new Event('change'));
});
