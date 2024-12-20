const step1 = document.getElementById('step1');
        const step2 = document.getElementById('step2');
        const step3 = document.getElementById('step3');
        const tableDetailsForm = document.getElementById('tableDetailsForm');
        const fileOption = document.getElementById('fileOption');
        const manualOption = document.getElementById('manualOption');
        const uploadStep = document.getElementById('uploadStep');
        const manualStep = document.getElementById('manualStep');
        const sqlForm = document.getElementById('sqlForm');
        const resultDiv = document.getElementById('result');

        // Обробка зміни вибору способу введення даних
        fileOption.addEventListener('change', function () {
            if (fileOption.checked) {
                uploadStep.style.display = 'block';
                manualStep.style.display = 'none';
            }
        });

        manualOption.addEventListener('change', function () {
            if (manualOption.checked) {
                uploadStep.style.display = 'none';
                manualStep.style.display = 'block';
            }
        });

        // Ініціалізація відразу після завантаження сторінки
        window.addEventListener('load', function () {
            if (fileOption.checked) {
                uploadStep.style.display = 'block';
                manualStep.style.display = 'none';
            } else {
                uploadStep.style.display = 'none';
                manualStep.style.display = 'block';
            }
        });

        function generateTableHTML(tableIndex, tableName = '', columns = []) {
    return `
        <div class="table-block">
            <h3>Таблиця ${tableIndex + 1}</h3>
            <input type="text" name="table_name_${tableIndex}" placeholder="Назва таблиці" value="${tableName}" required>
            <div id="columns_${tableIndex}">
                <h4>Стовпці</h4>
                ${columns
                    .map((col, colIndex) => generateColumnHTML(tableIndex, colIndex, col))
                    .join('')}
            </div>
            <div class="column-actions">
                <button type="button" class="add-column-btn" onclick="addColumn(${tableIndex})">
                    <i class="fas fa-plus"></i>
                </button>
            </div>
        </div>
    `;
}

function generateColumnHTML(tableIndex, columnIndex, column = {}) {
    const {
        name = '',
        type = 'INTEGER',
        primaryKey = false,
        notNull = false,
        uniqueKey = false,
        foreignKey = ''
    } = column;

    return `
        <div class="column-input">
            <input type="text" name="column_name_${tableIndex}_${columnIndex}" placeholder="Назва стовпця" value="${name}" required>
            <select name="column_type_${tableIndex}_${columnIndex}">
                <option value="INTEGER" ${type === 'INTEGER' ? 'selected' : ''}>INTEGER</option>
                <option value="TEXT" ${type === 'TEXT' ? 'selected' : ''}>TEXT</option>
                <option value="REAL" ${type === 'REAL' ? 'selected' : ''}>REAL</option>
                <option value="BOOLEAN" ${type === 'BOOLEAN' ? 'selected' : ''}>BOOLEAN</option>
                <option value="NUMERIC" ${type === 'NUMERIC' ? 'selected' : ''}>NUMERIC</option>
                <option value="TIME" ${type === 'TIME' ? 'selected' : ''}>TIME</option>
                <option value="DATE" ${type === 'DATE' ? 'selected' : ''}>DATE</option>
            </select>
            <label>
                <input type="checkbox" name="column_primaryKey_${tableIndex}_${columnIndex}" ${primaryKey ? 'checked' : ''}>
                Первинний
            </label>
            <label>
                <input type="checkbox" name="column_notNull_${tableIndex}_${columnIndex}" ${notNull ? 'checked' : ''}>
                NOT NULL
            </label>
            <label>
                <input type="checkbox" name="column_uniqueKey_${tableIndex}_${columnIndex}" ${uniqueKey ? 'checked' : ''}>
                Унікальний
            </label>
            <input type="text" name="column_foreignKey_${tableIndex}_${columnIndex}" placeholder="Зовнішній ключ (таблиця.стовпець)" value="${foreignKey}">
            <div class="column-actions">
                <button type="button" class="remove-column-btn" onclick="removeColumn(${tableIndex}, ${columnIndex})">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </div>
    `;
}



        document.getElementById('uploadForm').onsubmit = async function (e) {
    e.preventDefault();
    const file = document.getElementById('fileInput').files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = async function (event) {
            const fileContent = event.target.result;
            const tableData = JSON.parse(fileContent);

            tableDetailsForm.innerHTML = '';
            tableData.forEach((table, i) => {
                tableDetailsForm.innerHTML += generateTableHTML(i, table.name, table.columns);
            });

            step1.style.display = 'none';
            step2.style.display = 'block';
        };

        reader.readAsText(file);
    } else {
        alert('Будь ласка, виберіть файл для завантаження.');
    }
};

        document.getElementById('tableCountForm').onsubmit = function (e) {
    e.preventDefault();
    const tableCount = parseInt(document.getElementById('tableCount').value, 10);

    tableDetailsForm.innerHTML = '';
    for (let i = 0; i < tableCount; i++) {
        tableDetailsForm.innerHTML += generateTableHTML(i);
    }

    step1.style.display = 'none';
    step2.style.display = 'block';
};

function addColumn(tableIndex) {
    const columnsDiv = document.getElementById(`columns_${tableIndex}`);
    const columnInputs = columnsDiv.querySelectorAll('.column-input');
    const columnIndex = columnInputs.length;

    const newColumnHTML = generateColumnHTML(tableIndex, columnIndex);
    columnsDiv.insertAdjacentHTML('beforeend', newColumnHTML);
}
function removeColumn(tableIndex, columnIndex) {
    const columnsDiv = document.getElementById(`columns_${tableIndex}`);
    const columnDiv = document.querySelector(`[name="column_name_${tableIndex}_${columnIndex}"]`).parentElement;
    columnsDiv.removeChild(columnDiv);

    const remainingColumns = columnsDiv.querySelectorAll('.column-input');
    remainingColumns.forEach((col, newIndex) => {
        col.querySelector('input[type="text"]').name = `column_name_${tableIndex}_${newIndex}`;
        col.querySelector('select').name = `column_type_${tableIndex}_${newIndex}`;
        col.querySelector('input[type="checkbox"][name^="column_primaryKey"]').name = `column_primaryKey_${tableIndex}_${newIndex}`;
        col.querySelector('input[type="checkbox"][name^="column_notNull"]').name = `column_notNull_${tableIndex}_${newIndex}`;
        col.querySelector('input[type="checkbox"][name^="column_uniqueKey"]').name = `column_uniqueKey_${tableIndex}_${newIndex}`;
        col.querySelector('input[name^="column_foreignKey"]').name = `column_foreignKey_${tableIndex}_${newIndex}`;
        col.querySelector('.remove-column-btn').setAttribute('onclick', `removeColumn(${tableIndex}, ${newIndex})`);
    });
}
// Створення таблиць
document.getElementById('createTablesBtn').addEventListener('click', async function () {
    const tableData = [];
    const tables = document.querySelectorAll('input[name^="table_name_"]');

    tables.forEach((input, i) => {
        const tableName = input.value;
        const columns = [];
        let columnIndex = 0;

        while (document.querySelector(`[name="column_name_${i}_${columnIndex}"]`)) {
            const columnName = document.querySelector(`[name="column_name_${i}_${columnIndex}"]`).value;
            const columnType = document.querySelector(`[name="column_type_${i}_${columnIndex}"]`).value;
            const isPrimaryKey = document.querySelector(`[name="column_primaryKey_${i}_${columnIndex}"]`).checked ? true : false;
            const isNotNull = document.querySelector(`[name="column_notNull_${i}_${columnIndex}"]`).checked ? true : false;
            const isUniqueKey = document.querySelector(`[name="column_uniqueKey_${i}_${columnIndex}"]`).checked ? true : false;
            const foreignKey = document.querySelector(`[name="column_foreignKey_${i}_${columnIndex}"]`).value.trim();

            columns.push({
                name: columnName,
                type: columnType,
                primaryKey: isPrimaryKey,
                notNull: isNotNull,
                uniqueKey: isUniqueKey,
                foreignKey: foreignKey
            });

            columnIndex++;
        }

        tableData.push({ name: tableName, columns: columns });
    });

    const response = await fetch('/initialize_tables', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tables: tableData })
    });

    const result = await response.json();

    if (result.success) {
        alert(result.message);
        step2.style.display = 'none';
        step3.style.display = 'block';
    } else {
        alert(result.message);
    }
});




        // Перехід до кроку 1
        document.getElementById('backToStep1').addEventListener('click', function () {
            step2.style.display = 'none';
            step1.style.display = 'block';
        });

        // Перехід до кроку 2
        document.getElementById('backToStep2').addEventListener('click', function () {
            step3.style.display = 'none';
            step2.style.display = 'block';
        });


        document.getElementById('sqlForm').onsubmit = async function (e) {
    e.preventDefault();

    const formData = new FormData(this);
    const sqlQuery = formData.get('sql_query'); // Отримуємо SQL-запит

    // Перевірка на більше одного запиту
    const multipleQueriesRegex = /;(?=(?:[^'"]|'[^']*'|"[^"]*")*$)/g; // Знаходить ";" поза лапками
    if (sqlQuery.trim().split(multipleQueriesRegex).filter(query => query.trim()).length > 1) {
        const resultDiv = document.getElementById('result');
        resultDiv.innerHTML = `<p style="color: red;">Помилка: Ви намагаєтеся виконати більше одного запиту одночасно. Введіть лише один запит.</p>`;
        return; // Зупиняємо виконання
    }

    // Якщо запит валідний, надсилаємо його на сервер
    const response = await fetch('/check_sql', {
        method: 'POST',
        body: formData
    });

    const result = await response.json();
    const resultDiv = document.getElementById('result'); // Блок для виводу результатів

    if (result.valid) {
        let output = `
            <p style="color: green;">${result.message}</p>
            <p>Час виконання запиту: ${result.execution_time.toFixed(4)} секунд</p>
            <p>${result.time_status}</p>
        `;

        // Якщо є дані результату (наприклад, SELECT)
        if (result.result_data) {
            const columns = result.result_data.columns; // Масив заголовків колонок
            const rows = result.result_data.rows;       // Масив рядків даних

            // Генеруємо HTML-таблицю
            output += '<table border="1" style="width: 100%; border-collapse: collapse; margin-top: 10px;">';
            output += '<thead><tr>';

            // Додаємо заголовки колонок
            columns.forEach(col => {
                output += `<th style="padding: 8px; background-color: #444; color: white;">${col}</th>`;
            });
            output += '</tr></thead><tbody>';

            // Додаємо рядки з даними
            rows.forEach(row => {
                output += '<tr>';
                row.forEach(cell => {
                    output += `<td style="padding: 8px; text-align: center;">${cell}</td>`;
                });
                output += '</tr>';
            });

            output += '</tbody></table>';
        }

        resultDiv.innerHTML = output; // Відображаємо результат у HTML
    } else {
        resultDiv.innerHTML = `<p style="color: red;">${result.message}</p>`;
    }
};

        // Скидання запиту
        document.getElementById('resetQueryBtn').addEventListener('click', function () {
            document.querySelector('textarea[name="sql_query"]').value = '';  // очищаємо поле
            resultDiv.innerHTML = '';  // очищаємо результат
        });

        // Початок роботи знову
        document.getElementById('resetAppBtn').addEventListener('click', function () {
            location.reload();  // перезавантажуємо сторінку для початку процесу знову
        });

        function toggleSidebar() {
            const sidebar = document.querySelector('.sidebar');
            const sidebarIcon = document.querySelector('.sidebar-icon');
            if (sidebar.style.left === '0px') {
                sidebar.style.left = '-250px'; // Приховати панель
            } else {
                sidebar.style.left = '0'; // Відкрити панель
            }
        }

        // Обробка кнопки для отримання підказок щодо оптимізації
        // Обробка кнопки для отримання підказок щодо оптимізації
        document.getElementById('optimizationTipsBtn').addEventListener('click', async function () {
            const sqlQuery = document.querySelector('textarea[name="sql_query"]').value;

            if (!sqlQuery) {
                alert('Будь ласка, введіть SQL-запит.');
                return;
            }

            const response = await fetch('/get_optimization_tips', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sql_query: sqlQuery })
            });

            const result = await response.json();

            if (result.tips && result.tips.length > 0) {
                const tipsDiv = document.getElementById('optimizationTips');
                tipsDiv.style.display = 'block';
                tipsDiv.innerHTML = '<h3>Підказки з оптимізації:</h3>';
                result.tips.forEach(tip => {
                    tipsDiv.innerHTML += `<p>${tip}</p>`;
                });
            } else {
                const tipsDiv = document.getElementById('optimizationTips');
                tipsDiv.style.display = 'block';
                tipsDiv.innerHTML = '<p>Немає підказок для цього запиту.</p>';
            }
        });

        document.getElementById('viewStructureBtn').addEventListener('click', async function() {
            const tableName = document.getElementById('tableSelect').value;
            const response = await fetch(`/get_table_structure/${tableName}`);
            const data = await response.json();

            if (data.error) {
                alert('Помилка: ' + data.error);
                return;
            }

            const tableBody = document.querySelector('#tableStructure tbody');
            tableBody.innerHTML = '';  // Очищуємо таблицю перед завантаженням нових даних

            data.forEach(row => {
                const newRow = `
                    <tr>
                        <td>${row.column_id}</td>
                        <td>${row.column_name}</td>
                        <td>${row.data_type}</td>
                        <td>${row.not_null ? 'Так' : 'Ні'}</td>
                        <td>${row.default_value || 'Немає'}</td>
                        <td>${row.primary_key ? 'Так' : 'Ні'}</td>
                    </tr>`;
                tableBody.innerHTML += newRow;
            });
        });




