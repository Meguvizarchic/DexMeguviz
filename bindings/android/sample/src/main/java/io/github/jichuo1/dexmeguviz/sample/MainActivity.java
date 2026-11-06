package io.github.jichuo1.dexmeguviz.sample;

import android.app.Activity;
import android.os.Bundle;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import io.github.jichuo1.dexmeguviz.ExpandResult;
import io.github.jichuo1.dexmeguviz.NativeEngine;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Optional host sample. Asset DEX is queried as bytes, never loaded as code. */
public final class MainActivity extends Activity {
    private volatile boolean destroyed;
    private TextView output;
    private Button run;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout content=new LinearLayout(this);content.setOrientation(LinearLayout.VERTICAL);
        int padding=(int)(20*getResources().getDisplayMetrics().density);content.setPadding(padding,padding,padding,padding);
        TextView intro=new TextView(this);intro.setText("DexMeguviz 示例\n读取项目自建 DEX，展示多来源与两跳展开结果。不会加载资产中的类，也不访问其他应用。");
        run=new Button(this);run.setText("运行查询");output=new TextView(this);output.setTextIsSelectable(true);
        content.addView(intro);content.addView(run);content.addView(output);
        ScrollView scroll=new ScrollView(this);scroll.addView(content,new ViewGroup.LayoutParams(-1,-2));setContentView(scroll);
        run.setOnClickListener(view -> startQuery());
    }
    private byte[] asset(String name) throws Exception {
        try(InputStream in=getAssets().open("dex/"+name);ByteArrayOutputStream out=new ByteArrayOutputStream()){
            byte[] buffer=new byte[4096];int count;
            while((count=in.read(buffer))!=-1){if(out.size()+count>1024*1024)throw new IllegalStateException("sample asset limit");out.write(buffer,0,count);}
            return out.toByteArray();
        }
    }
    private void startQuery() {
        run.setEnabled(false);output.setText("正在后台读取与查询…");
        new Thread(() -> {
            String report;
            try {
                String[] names={"amb-a.dex","amb-b1.dex","amb-b2.dex","amb-c1.dex","amb-c2.dex"};
                byte[][] bytes=new byte[names.length][];for(int i=0;i<names.length;i++)bytes[i]=asset(names[i]);
                byte[] query=("{\"schema_version\":1,\"required_capabilities\":[\"bounded_expand\"],"+
                    "\"relation\":{\"op\":\"bounded_expand\",\"input\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"owner\":\"Lamb/A;\"}},"+
                    "\"min_depth\":2,\"max_depth\":2,\"output\":\"paths\"},\"intent\":\"enumerate\",\"max_results\":64,\"max_work\":1000000}").getBytes(StandardCharsets.UTF_8);
                try(NativeEngine.SourceSetSnapshot snapshot=NativeEngine.openRawDexSet(bytes,names)){
                    ExpandResult result=snapshot.queryExpand(query);int paths=0;for(int i=0;i<result.rowCount();i++)paths+=result.row(i).pathCount();
                    report="查询已返回\n执行状态："+result.executionStatus+"\n来源数："+result.sourceCount()+"\n结果行："+result.rowCount()+"\n路径数："+paths+"\n前沿数："+result.frontierCount()+
                        "\n范围完整声明："+result.profile.scopeComplete+"\n\n"+result.queryId+"\n\n这是静态查询结果，不代表加载来源、运行时分派或业务验收。";
                }
            }catch(Exception|LinkageError error){report="查询未完成："+error.getClass().getSimpleName()+"\n"+String.valueOf(error.getMessage());}
            final String text=report;runOnUiThread(() -> {if(!destroyed){output.setText(text);run.setEnabled(true);}});
        },"dexmeguviz-sample-query").start();
    }
    @Override public void onDestroy(){destroyed=true;super.onDestroy();}
}
