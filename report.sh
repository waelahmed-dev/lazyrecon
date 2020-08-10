report(){
  subdomain=$(echo $line | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g')
  echo "${yellow}	[+] Generating report for $subdomain"

  dirsearchfile=$(ls ../dirsearch/reports/$subdomain/ | grep -v old)

  touch ./$1/$foldername/reports/$subdomain.html
  echo '<html><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge">' >> ./$1/$foldername/reports/$subdomain.html
  echo "<head>" >> ./$1/$foldername/reports/$subdomain.html
  echo "<title>Recon Report for $subdomain</title>
  <style>.status.fourhundred{color:#00a0fc}.status.redirect{color:#d0b200}.status.fivehundred{color:#DD4A68}.status.jackpot{color:#0dee00}.status.weird{color:#cc00fc}img{padding:5px;width:360px}img:hover{box-shadow:0 0 2px 1px rgba(0,140,186,.5)}pre{font-family:Inconsolata,monospace}pre{margin:0 0 20px}pre{overflow-x:auto}article,header,img{display:block}#wrapper:after,.blog-description:after,.clearfix:after{content:}.container{position:relative}html{line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}h1{margin:.67em 0}h1,h2{margin-bottom:20px}a{background-color:transparent;-webkit-text-decoration-skip:objects;text-decoration:none}.container,table{width:100%}.site-header{overflow:auto}.post-header,.post-title,.site-header,.site-title,h1,h2{text-transform:uppercase}p{line-height:1.5em}pre,table td{padding:10px}h2{padding-top:40px;font-weight:900}a{color:#00a0fc}body,html{height:100%}body{margin:0;background:#fefefe;color:#424242;font-family:Raleway,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,'Helvetica Neue',Arial,sans-serif;font-size:24px}h1{font-size:35px}h2{font-size:28px}p{margin:0 0 30px}pre{background:#f1f0ea;border:1px solid #dddbcc;border-radius:3px;font-size:16px}.row{display:flex}.column{flex:100%}table tbody>tr:nth-child(odd)>td,table tbody>tr:nth-child(odd)>th{background-color:#f7f7f3}table th{padding:0 10px 10px;text-align:left}.post-header,.post-title,.site-header{text-align:center}table tr{border-bottom:1px dotted #aeadad}::selection{background:#fff5b8;color:#000;display:block}::-moz-selection{background:#fff5b8;color:#000;display:block}.clearfix:after{display:table;clear:both}.container{max-width:100%}#wrapper{height:auto;min-height:100%;margin-bottom:-265px}#wrapper:after{display:block;height:265px}.site-header{padding:40px 0 0}.site-title{float:left;font-size:14px;font-weight:600;margin:0}.site-title a{float:left;background:#00a0fc;color:#fefefe;padding:5px 10px 6px}.post-container-left{width:49%;float:left;margin:auto}.post-container-right{width:49%;float:right;margin:auto}.post-header{border-bottom:1px solid #333;margin:0 0 50px;padding:0}.post-title{font-size:55px;font-weight:900;margin:15px 0}.blog-description{color:#aeadad;font-size:14px;font-weight:600;line-height:1;margin:25px 0 0;text-align:center}.single-post-container{margin-top:50px;padding-left:15px;padding-right:15px;box-sizing:border-box}body.dark{background-color:#1e2227;color:#fff}body.dark pre{background:#282c34}body.dark table tbody>tr:nth-child(odd)>td,body.dark table tbody>tr:nth-child(odd)>th{background:#282c34} table tbody>tr:nth-child(even)>th{background:#1e2227} input{font-family:Inconsolata,monospace} body.dark .status.redirect{color:#ecdb54} body.dark input{border:1px solid ;border-radius: 3px; background:#282c34;color: white} body.dark label{color:#f1f0ea} body.dark pre{color:#fff}</style>
  <script>
    document.addEventListener('DOMContentLoaded', (event) => {
        ((localStorage.getItem('mode') || 'dark') === 'dark') ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')
    })
  </script>" >> ./$1/$foldername/reports/$subdomain.html
  echo '<link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/material-design-lite/1.1.0/material.min.css">
  <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.19/css/dataTables.material.min.css">
  <script type="text/javascript" src="https://code.jquery.com/jquery-3.3.1.js"></script>
  <script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.10.19/js/jquery.dataTables.js"></script><script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.10.19/js/dataTables.material.min.js"></script>'>> ./$1/$foldername/reports/$subdomain.html
  echo '<script>$(document).ready( function () {
    $("#myTable").DataTable({
        "paging":   true,
        "ordering": true,
        "info":     true,
	     "autoWidth": true,
            "columns": [{ "width": "5%" },{ "width": "5%" },null],
                "lengthMenu": [[10, 25, 50,100, -1], [10, 25, 50,100, "All"]],

    });
  } );</script></head>'>> ./$1/$foldername/reports/$subdomain.html

  echo '<body class="dark"><header class="site-header">
  <div class="site-title"><p>' >> ./$1/$foldername/reports/$subdomain.html
  echo "<a style=\"cursor: pointer\" onclick=\"localStorage.setItem('mode', (localStorage.getItem('mode') || 'dark') === 'dark' ? 'bright' : 'dark'); localStorage.getItem('mode') === 'dark' ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')\" title=\"Switch to light or dark theme\">🌓 Light|dark mode</a>
  </p>
  </div>
  </header>" >> ./$1/$foldername/reports/$subdomain.html
  echo '<div id="wrapper"><div id="container">'  >> ./$1/$foldername/reports/$subdomain.html
  echo "<h1 class=\"post-title\" itemprop=\"name headline\">Recon Report for <a href=\"http://$subdomain\">$subdomain</a></h1>" >> ./$1/$foldername/reports/$subdomain.html
  echo "<p class=\"blog-description\">Generated by LazyRecon on $(date) </p>" >> ./$1/$foldername/reports/$subdomain.html
  echo '<div class="container single-post-container">
  <article class="post-container-left" itemscope="" itemtype="http://schema.org/BlogPosting">
  <header class="post-header">
  </header>
  <div class="post-content clearfix" itemprop="articleBody">
  <h2>Content Discovery</h2>' >> ./$1/$foldername/reports/$subdomain.html



  echo "<table id='myTable' class='stripe'>" >> ./$1/$foldername/reports/$subdomain.html
  echo "<thead><tr>
  <th>Status Code</th>
  <th>Content-Length</th>
  <th>Url</th>
  </tr></thead><tbody>" >> ./$1/$foldername/reports/$subdomain.html

  cat ~/tools/dirsearch/reports/$subdomain/$dirsearchfile | while read nline; do
  status_code=$(echo "$nline" | awk '{print $1}')
  size=$(echo "$nline" | awk '{print $2}')
  url=$(echo "$nline" | awk '{print $3}')
  path=${url#*[0-9]/}
  echo "<tr>" >> ./$1/$foldername/reports/$subdomain.html
  if [[ "$status_code" == *20[012345678]* ]]; then
    echo "<td class='status jackpot'>$status_code</td><td class='status jackpot'>$size</td><td><a class='status jackpot' href='$url'>/$path</a></td>" >> ./$1/$foldername/reports/$subdomain.html
  elif [[ "$status_code" == *30[012345678]* ]]; then
    echo "<td class='status redirect'>$status_code</td><td class='status redirect'>$size</td><td><a class='status redirect' href='$url'>/$path</a></td>" >> ./$1/$foldername/reports/$subdomain.html
  elif [[ "$status_code" == *40[012345678]* ]]; then
    echo "<td class='status fourhundred'>$status_code</td><td class='status fourhundred'>$size</td><td><a class='status fourhundred' href='$url'>/$path</a></td>" >> ./$1/$foldername/reports/$subdomain.html
  elif [[ "$status_code" == *50[012345678]* ]]; then
    echo "<td class='status fivehundred'>$status_code</td><td class='status fivehundred'>$size</td><td><a class='status fivehundred' href='$url'>/$path</a></td>" >> ./$1/$foldername/reports/$subdomain.html
  else
     echo "<td class='status weird'>$status_code</td><td class='status weird'>$size</td><td><a class='status weird' href='$url'>/$path</a></td>" >> ./$1/$foldername/reports/$subdomain.html
  fi
  echo "</tr>">> ./$1/$foldername/reports/$subdomain.html
  done

  echo "</tbody></table></div>" >> ./$1/$foldername/reports/$subdomain.html

  echo '</article><article class="post-container-right" itemscope="" itemtype="http://schema.org/BlogPosting">
  <header class="post-header">
  </header>
  <div class="post-content clearfix" itemprop="articleBody">
  <h2>Screenshots</h2>
  <pre style="max-height: 340px;overflow-y: scroll">' >> ./$1/$foldername/reports/$subdomain.html
  echo '<div class="row">
  <div class="column">
  Port 80' >> ./$1/$foldername/reports/$subdomain.html
  scpath=$(echo "$subdomain" | sed 's/\./_/g')
  httpsc=$(ls ./$1/$foldername/aqua_out/screenshots/http__$scpath*  2>/dev/null)
  echo "<a href=\"../../../$httpsc\"><img/src=\"../../../$httpsc\"></a> " >> ./$1/$foldername/reports/$subdomain.html
  echo '</div>
    <div class="column">
  Port 443' >> ./$1/$foldername/reports/$subdomain.html
  httpssc=$(ls ./$1/$foldername/aqua_out/screenshots/https__$scpath*  2>/dev/null)
  echo "<a href=\"../../../$httpssc\"><img/src=\"../../../$httpssc\"></a>" >> ./$1/$foldername/reports/$subdomain.html
  echo "</div></div></pre>" >> ./$1/$foldername/reports/$subdomain.html
  #echo "<h2>Dig Info</h2><pre>$(dig $subdomain)</pre>" >> ./$1/$foldername/reports/$subdomain.html
  echo "<h2>Host Info</h2><pre>$(host $subdomain)</pre>" >> ./$1/$foldername/reports/$subdomain.html
  echo "<h2>Response Headers</h2><pre>" >> ./$1/$foldername/reports/$subdomain.html

  echo "</pre>" >> ./$1/$foldername/reports/$subdomain.html
  echo "<h2>NMAP Results</h2>
  <pre>
  $(nmap -sV -T3 -Pn -p2075,2076,6443,3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,7447,7080,8880,8983,5673,7443,19000,19080 $subdomain  |  grep -E 'open|filtered|closed')
  </pre>
  </div></article></div>
  </div></div></body></html>" >> ./$1/$foldername/reports/$subdomain.html
}


master_report(){
  #this code will generate the html report for target it will have an overview of the scan
  echo '<html>
  <head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">' >> ./$1/$foldername/master_report.html
  echo "<title>Recon Report for $1</title>
  <style>.status.redirect{color:#d0b200}.status.fivehundred{color:#DD4A68}.status.jackpot{color:#0dee00}img{padding:5px;width:360px}img:hover{box-shadow:0 0 2px 1px rgba(0,140,186,.5)}pre{font-family:Inconsolata,monospace}pre{margin:0 0 20px}pre{overflow-x:auto}article,header,img{display:block}#wrapper:after,.blog-description:after,.clearfix:after{content:}.container{position:relative}html{line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}h1{margin:.67em 0}h1,h2{margin-bottom:20px}a{background-color:transparent;-webkit-text-decoration-skip:objects;text-decoration:none}.container,table{width:100%}.site-header{overflow:auto}.post-header,.post-title,.site-header,.site-title,h1,h2{text-transform:uppercase}p{line-height:1.5em}pre,table td{padding:10px}h2{padding-top:40px;font-weight:900}a{color:#00a0fc}body,html{height:100%}body{margin:0;background:#fefefe;color:#424242;font-family:Raleway,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,'Helvetica Neue',Arial,sans-serif;font-size:24px}h1{font-size:35px}h2{font-size:28px}p{margin:0 0 30px}pre{background:#f1f0ea;border:1px solid #dddbcc;border-radius:3px;font-size:16px}.row{display:flex}.column{flex:100%}table tbody>tr:nth-child(odd)>td,table tbody>tr:nth-child(odd)>th{background-color:#f7f7f3}table th{padding:0 10px 10px;text-align:left}.post-header,.post-title,.site-header{text-align:center}table tr{border-bottom:1px dotted #aeadad}::selection{background:#fff5b8;color:#000;display:block}::-moz-selection{background:#fff5b8;color:#000;display:block}.clearfix:after{display:table;clear:both}.container{max-width:100%}#wrapper{height:auto;min-height:100%;margin-bottom:-265px}#wrapper:after{display:block;height:265px}.site-header{padding:40px 0 0}.site-title{float:left;font-size:14px;font-weight:600;margin:0}.site-title a{float:left;background:#00a0fc;color:#fefefe;padding:5px 10px 6px}.post-container-left{width:49%;float:left;margin:auto}.post-container-right{width:49%;float:right;margin:auto}.post-header{border-bottom:1px solid #333;margin:0 0 50px;padding:0}.post-title{font-size:55px;font-weight:900;margin:15px 0}.blog-description{color:#aeadad;font-size:14px;font-weight:600;line-height:1;margin:25px 0 0;text-align:center}.single-post-container{margin-top:50px;padding-left:15px;padding-right:15px;box-sizing:border-box}body.dark{background-color:#1e2227;color:#fff}body.dark pre{background:#282c34}body.dark table tbody>tr:nth-child(odd)>td,body.dark table tbody>tr:nth-child(odd)>th{background:#282c34}input{font-family:Inconsolata,monospace} body.dark .status.redirect{color:#ecdb54} body.dark input{border:1px solid ;border-radius: 3px; background:#282c34;color: white} body.dark label{color:#f1f0ea} body.dark pre{color:#fff}</style>
  <script>
  document.addEventListener('DOMContentLoaded', (event) => {
    ((localStorage.getItem('mode') || 'dark') === 'dark') ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')
  })
  </script>" >> ./$1/$foldername/master_report.html
  echo '<link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/material-design-lite/1.1.0/material.min.css">
  <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.19/css/dataTables.material.min.css">
    <script type="text/javascript" src="https://code.jquery.com/jquery-3.3.1.js"></script>
  <script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.10.19/js/jquery.dataTables.js"></script><script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.10.19/js/dataTables.material.min.js"></script>'>> ./$1/$foldername/master_report.html
  echo '<script>$(document).ready( function () {
      $("#myTable").DataTable({
          "paging":   true,
          "ordering": true,
          "info":     false,
    "lengthMenu": [[10, 25, 50,100, -1], [10, 25, 50,100, "All"]],
      });
  } );</script></head>'>> ./$1/$foldername/master_report.html



  echo '<body class="dark"><header class="site-header">
  <div class="site-title"><p>' >> ./$1/$foldername/master_report.html
  echo "<a style=\"cursor: pointer\" onclick=\"localStorage.setItem('mode', (localStorage.getItem('mode') || 'dark') === 'dark' ? 'bright' : 'dark'); localStorage.getItem('mode') === 'dark' ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')\" title=\"Switch to light or dark theme\">🌓 Light|dark mode</a>
  </p>
  </div>
  </header>" >> ./$1/$foldername/master_report.html


  echo '<div id="wrapper"><div id="container">' >> ./$1/$foldername/master_report.html
  echo "<h1 class=\"post-title\" itemprop=\"name headline\">Recon Report for <a href=\"http://$1\">$1</a></h1>" >> ./$1/$foldername/master_report.html
  echo "<p class=\"blog-description\">Generated by LazyRecon on $(date) </p>" >> ./$1/$foldername/master_report.html
  echo '<div class="container single-post-container">
  <article class="post-container-left" itemscope="" itemtype="http://schema.org/BlogPosting">
  <header class="post-header">
  </header>
  <div class="post-content clearfix" itemprop="articleBody">
  <h2>Total scanned subdomains</h2>
  <table id="myTable" class="stripe">
  <thead>
  <tr>
  <th>Subdomains</th>
  <th>Scanned Urls</th>
  </tr>
  </thead>
  <tbody>' >> ./$1/$foldername/master_report.html


  cat ./$1/$foldername/live.txt | sed 's/\http\:\/\///g' | sed 's/\https\:\/\///g'  | while read nline; do
    diresults=$(ls ../dirsearch/reports/$nline/ | grep -v old)
    echo "<tr>
    <td><a href='./reports/$nline.html'>$nline</a></td>
    <td>$(wc -l ../dirsearch/reports/$nline/$diresults | awk '{print $1}')</td>
    </tr>" >> ./$1/$foldername/master_report.html
  done
  echo "</tbody></table>

  echo '</article><article class="post-container-right" itemscope="" itemtype="http://schema.org/BlogPosting">
  <header class="post-header"></header><div class="post-content clearfix" itemprop="articleBody">' >> ./$1/$foldername/master_report.html

  echo "<h2>Dig Info</h2><pre>
    $(dig $1)
    </pre>" >> ./$1/$foldername/master_report.html
  echo "<h2>Host Info</h2>
  <pre>
  $(host $1)
  </pre>" >> ./$1/$foldername/master_report.html

  echo "<h2>NMAP Results</h2>
  <pre>
  $(nmap -sV -T3 -Pn -p3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,7447,7080,8880,8983,5673,7443,19000,19080 $1 |  grep -E 'open|filtered|closed')
  </pre>
  </div></article></div>
  </div></div></body></html>" >> ./$1/$foldername/master_report.html
}
