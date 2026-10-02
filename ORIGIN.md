# Origin and boundaries

This is an independent, source-informed, complete **new-scope** defensive tool. It is not a claim to rewrite all of the upstream project or to be behaviorally equivalent to it. Offline configuration evidence does not prove effective runtime protection, authorization, CVP eligibility, or approval.

Upstream references are frozen below. Only policy data explicitly named in NOTICE is bundled; other upstream implementation code and documentation are not copied into the wheel. Source license labels describe references; the new implementation license is MIT.

- `COPYING` at `5019f0ccae0c07ba9e50abc794596f220fff65b9`, SHA-256 `8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643`: https://raw.githubusercontent.com/firewalld/firewalld/5019f0ccae0c07ba9e50abc794596f220fff65b9/COPYING
- `doc/xml/firewalld.zone.xml` at `5019f0ccae0c07ba9e50abc794596f220fff65b9`, SHA-256 `99e07c8250639959dcf29e34f19db893b560fdbaccaf264bd14b47042f897329`: https://raw.githubusercontent.com/firewalld/firewalld/5019f0ccae0c07ba9e50abc794596f220fff65b9/doc/xml/firewalld.zone.xml
- `doc/xml/firewalld.service.xml` at `5019f0ccae0c07ba9e50abc794596f220fff65b9`, SHA-256 `43948c5bd761929583a04b84bb4a3435bf5d13bc163abea5d06f49c56b76aef0`: https://raw.githubusercontent.com/firewalld/firewalld/5019f0ccae0c07ba9e50abc794596f220fff65b9/doc/xml/firewalld.service.xml
- `doc/xml/firewalld.richlanguage.xml` at `5019f0ccae0c07ba9e50abc794596f220fff65b9`, SHA-256 `fed349e14062b3a28795bf5846d0e2a7e2a907fbd922c11f5b973450d60f7ab6`: https://raw.githubusercontent.com/firewalld/firewalld/5019f0ccae0c07ba9e50abc794596f220fff65b9/doc/xml/firewalld.richlanguage.xml

- Hidden child semantics additionally reference the frozen SAX handlers `src/firewall/core/io/zone.py`, `policy.py`, `io_object.py` at `5019f0ccae0c07ba9e50abc794596f220fff65b9`: https://github.com/firewalld/firewalld/tree/5019f0ccae0c07ba9e50abc794596f220fff65b9/src/firewall/core/io . Those functions are not bundled or used at runtime; this profile strictly rejects children/attributes of text-only short/description.
