//! A real IFC input, two persistent registries and visible authorization outcomes.
use crate::{
    client::{Client, Reference},
    registry::{self, Registry},
    release,
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};
use tokio::task::JoinHandle;
use uuid::Uuid;

pub const IFC: &str = r#"ISO-10303-21;
HEADER;
FILE_DESCRIPTION(('IFCX OCI showcase'),'2;1');
FILE_NAME('showcase.ifc','2026-10-28T09:00:00',(''),(''),'ifcx-oci','ifcx-oci','');
FILE_SCHEMA(('IFC4'));
ENDSEC;
DATA;
#1=IFCPROJECT('0000000000000000000001',$,'Showcase',$,$,$,$,(#11),#21);
#10=IFCCARTESIANPOINT((0.,0.,0.));
#11=IFCGEOMETRICREPRESENTATIONCONTEXT($,'Model',3,0.00001,#12,$);
#12=IFCAXIS2PLACEMENT3D(#10,$,$);
#14=IFCRECTANGLEPROFILEDEF(.AREA.,$,$,4.,0.2);
#15=IFCDIRECTION((0.,0.,1.));
#19=IFCEXTRUDEDAREASOLID(#14,#12,#15,3.);
#20=IFCSIUNIT(*,.LENGTHUNIT.,$,.METRE.);
#21=IFCUNITASSIGNMENT((#20));
#24=IFCSHAPEREPRESENTATION(#11,'Body','SweptSolid',(#19));
#25=IFCPRODUCTDEFINITIONSHAPE($,$,(#24));
#31=IFCLOCALPLACEMENT($,#12);
#32=IFCCARTESIANPOINT((5.,0.,0.));
#33=IFCAXIS2PLACEMENT3D(#32,$,$);
#34=IFCLOCALPLACEMENT($,#33);
#40=IFCWALL('0000000000000000000040',$,'Wall A',$,$,#31,#25,$,.NOTDEFINED.);
#41=IFCWALL('0000000000000000000041',$,'Wall B',$,$,#34,#25,$,.NOTDEFINED.);
#50=IFCWALLTYPE('0000000000000000000050',$,'Shared wall type',$,$,$,$,$,$,.NOTDEFINED.);
#51=IFCRELDEFINESBYTYPE('0000000000000000000051',$,$,$,(#40,#41),#50);
#60=IFCPROPERTYSINGLEVALUE('FireRating',$,IFCLABEL('EI60'),$);
#61=IFCPROPERTYSINGLEVALUE('Count',$,IFCINTEGER(0),$);
#62=IFCPROPERTYSINGLEVALUE('External',$,IFCBOOLEAN(.F.),$);
#63=IFCPROPERTYSINGLEVALUE('Unset',$,$,$);
#64=IFCPROPERTYSET('0000000000000000000064',$,'Pset_Showcase',$,(#60,#61,#62,#63));
#65=IFCRELDEFINESBYPROPERTIES('0000000000000000000065',$,$,$,(#40,#41),#64);
#70=IFCQUANTITYLENGTH('Length',$,$,4.,$);
#71=IFCELEMENTQUANTITY('0000000000000000000071',$,'BaseQuantities',$,$,(#70));
#72=IFCRELDEFINESBYPROPERTIES('0000000000000000000072',$,$,$,(#40),#71);
ENDSEC;
END-ISO-10303-21;
"#;

struct Running(JoinHandle<()>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn oras_run(
    binary: &Path,
    config: &Path,
    args: &[String],
    password: Option<&str>,
    cwd: &Path,
) -> Result<Output> {
    let mut command = Command::new(binary);
    command.args(args);
    if args.first().is_some_and(|arg| arg == "cp") {
        command
            .arg("--from-registry-config")
            .arg(config)
            .arg("--to-registry-config")
            .arg(config);
    } else {
        command.arg("--registry-config").arg(config);
    }
    command
        .current_dir(cwd)
        .stdin(if password.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .context("Start the independent ORAS client")?;
    if let Some(password) = password {
        writeln!(
            child.stdin.take().context("ORAS password input")?,
            "{password}"
        )?;
    }
    Ok(child.wait_with_output()?)
}
fn required(output: Output) -> Result<()> {
    ensure!(
        output.status.success(),
        "ORAS failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

async fn interop(
    binary: &Path,
    root: &Path,
    a: &str,
    b: &str,
    writer_pw: &str,
    reader_pw: &str,
    client: &Client,
) -> Result<Value> {
    let config = tempfile::Builder::new()
        .prefix(".oras-auth-")
        .tempdir_in(root)?;
    let credentials = config.path().join("config.json");
    let release = root.join("release");
    for host in [a, b] {
        required(oras_run(
            binary,
            &credentials,
            &[
                "login".into(),
                host.into(),
                "--plain-http".into(),
                "--username".into(),
                "writer".into(),
                "--password-stdin".into(),
            ],
            Some(writer_pw),
            root,
        )?)?;
    }
    let mut push = vec![
        "push".into(),
        "--plain-http".into(),
        "--artifact-type".into(),
        release::ARTIFACT_TYPE.into(),
        format!("{a}/project/oras:issued"),
        "index.json:application/json".into(),
    ];
    push.extend(
        release::read_index(&release)?
            .files
            .iter()
            .map(|f| format!("{}:{}", f.path, f.media_type)),
    );
    required(oras_run(binary, &credentials, &push, None, &release)?)?;
    let (raw, _) = client
        .manifest(&Reference::parse(
            &format!("{a}/project/oras:issued"),
            true,
        )?)
        .await?;
    let digest = release::digest(&raw);
    required(oras_run(
        binary,
        &credentials,
        &[
            "cp".into(),
            "--from-plain-http".into(),
            "--to-plain-http".into(),
            format!("{a}/project/oras@{digest}"),
            format!("{b}/deliver/oras:issued"),
        ],
        None,
        root,
    )?)?;
    let (copied, _) = client
        .manifest(&Reference::parse(
            &format!("{b}/deliver/oras:issued"),
            true,
        )?)
        .await?;
    ensure!(
        release::digest(&copied) == digest,
        "ORAS changed the manifest digest during copy"
    );
    let received = root.join("oras-received");
    required(oras_run(
        binary,
        &credentials,
        &[
            "pull".into(),
            "--plain-http".into(),
            "--output".into(),
            received.to_string_lossy().into(),
            format!("{b}/deliver/oras@{digest}"),
        ],
        None,
        root,
    )?)?;
    release::verify(&received)?;
    client
        .pull(
            &format!("{a}/project/oras@{digest}"),
            &root.join("rust-read-oras"),
        )
        .await?;
    let reader_config = config.path().join("reader.json");
    required(oras_run(
        binary,
        &reader_config,
        &[
            "login".into(),
            a.into(),
            "--plain-http".into(),
            "--username".into(),
            "reader".into(),
            "--password-stdin".into(),
        ],
        Some(reader_pw),
        root,
    )?)?;
    required(oras_run(
        binary,
        &reader_config,
        &[
            "manifest".into(),
            "fetch".into(),
            "--plain-http".into(),
            format!(
                "{a}/project/model@{}",
                client
                    .manifest(&Reference::parse(
                        &format!("{a}/project/model:issued"),
                        true
                    )?)
                    .await
                    .map(|(v, _)| release::digest(&v))?
            ),
        ],
        None,
        root,
    )?)?;
    let denied = oras_run(
        binary,
        &reader_config,
        &[
            "push".into(),
            "--plain-http".into(),
            "--artifact-type".into(),
            "application/vnd.example.receipt".into(),
            format!("{a}/project/model:reader-denied"),
            "index.json:application/json".into(),
        ],
        None,
        &release,
    )?;
    ensure!(
        !denied.status.success(),
        "ORAS reader unexpectedly pushed an artifact"
    );
    Ok(
        json!({"client":"ORAS","authenticatedPush":true,"crossRegistryCopy":true,"pullAndVerify":true,"rustReadOrasArtifact":true,"readerPushDenied":true,"manifestDigestPreserved":digest}),
    )
}

pub async fn run(output: &Path, oras: Option<&Path>) -> Result<Value> {
    ensure!(!output.exists(), "Demo output must not already exist");
    fs::create_dir_all(output)?;
    let output = fs::canonicalize(output)?;
    eprintln!("1/5 Convert a generated IFC containing two placed walls, shared type, properties and quantities");
    let source = output.join("showcase.ifc");
    fs::write(&source, IFC)?;
    let release = output.join("release");
    let conversion = release::convert(&source, &release, "showcase", false)?;
    ensure!(
        conversion.geometry["triangles"].as_u64().unwrap_or(0) > 0,
        "Demo did not tessellate geometry"
    );
    let a = Registry::open(output.join("company-a"))?;
    let b = Registry::open(output.join("company-b"))?;
    let writer_pw = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let reader_pw = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    a.auth.add_user(
        "writer",
        &writer_pw,
        &[
            "project/model:pull,push".into(),
            "project/oras:pull,push".into(),
        ],
    )?;
    b.auth.add_user(
        "writer",
        &writer_pw,
        &[
            "deliver/model:pull,push".into(),
            "deliver/oras:pull,push".into(),
        ],
    )?;
    a.auth
        .add_user("reader", &reader_pw, &["project/model:pull".into()])?;
    let la = registry::bind("127.0.0.1:0".parse()?).await?;
    let lb = registry::bind("127.0.0.1:0".parse()?).await?;
    let host_a = la.local_addr()?.to_string();
    let host_b = lb.local_addr()?.to_string();
    let ra = a.clone();
    let rb = b.clone();
    let _a = Running(tokio::spawn(async move {
        if let Err(e) = registry::serve(la, ra).await {
            eprintln!("Registry A: {e}");
        }
    }));
    let _b = Running(tokio::spawn(async move {
        if let Err(e) = registry::serve(lb, rb).await {
            eprintln!("Registry B: {e}");
        }
    }));
    eprintln!("2/5 Login through OCI Bearer discovery; obtain exact repository/action scopes");
    let mut writer = Client::new(output.join("writer-auth.json"), true)?;
    let writer_a = writer
        .login(
            &host_a,
            "writer",
            &writer_pw,
            &[
                "project/model:pull,push".into(),
                "project/oras:pull,push".into(),
            ],
        )
        .await?;
    let writer_b = writer
        .login(
            &host_b,
            "writer",
            &writer_pw,
            &[
                "deliver/model:pull,push".into(),
                "deliver/oras:pull,push".into(),
            ],
        )
        .await?;
    eprintln!("3/5 Push → independent-registry copy → pinned pull → verify");
    let digest = writer
        .push(&release, &format!("{host_a}/project/model:issued"))
        .await?;
    let copied = writer
        .copy(
            &format!("{host_a}/project/model@{digest}"),
            &format!("{host_b}/deliver/model:issued"),
        )
        .await?;
    let (pulled, verification) = writer
        .pull(
            &format!("{host_b}/deliver/model@{copied}"),
            &output.join("received"),
        )
        .await?;
    ensure!(
        digest == copied && digest == pulled,
        "Manifest digest changed during delivery"
    );
    eprintln!("4/5 Reader pull succeeds; push and cross-repository access are denied");
    let mut reader = Client::new(output.join("reader-auth.json"), true)?;
    let reader_access = reader
        .login(
            &host_a,
            "reader",
            &reader_pw,
            &["project/model:pull,push".into()],
        )
        .await?;
    reader
        .pull(
            &format!("{host_a}/project/model@{digest}"),
            &output.join("reader-received"),
        )
        .await?;
    ensure!(
        reader
            .push(&release, &format!("{host_a}/project/model:forbidden"))
            .await
            .is_err(),
        "Reader unexpectedly has push permission"
    );
    ensure!(
        reader
            .copy(
                &format!("{host_a}/project/model@{digest}"),
                &format!("{host_a}/private/model:forbidden")
            )
            .await
            .is_err(),
        "Reader unexpectedly has cross-repository access"
    );
    let (expired, _) = a
        .auth
        .issue("writer", &["repository:project/model:pull".into()], 0)?;
    let http = reqwest::Client::new();
    ensure!(
        http.get(format!("http://{host_a}/v2/"))
            .bearer_auth(expired)
            .send()
            .await?
            .status()
            == 401,
        "Expired token was accepted"
    );
    ensure!(
        http.get(format!("http://{host_a}/v2/"))
            .bearer_auth("invalid.jwt.signature")
            .send()
            .await?
            .status()
            == 401,
        "Invalid token was accepted"
    );
    let independent = if let Some(binary) = oras {
        eprintln!("5/5 ORAS authenticated push, cross-registry copy, pull and denied reader push");
        Some(
            interop(
                binary, &output, &host_a, &host_b, &writer_pw, &reader_pw, &writer,
            )
            .await?,
        )
    } else {
        eprintln!(
            "5/5 ORAS not requested; use the Nix demo app to include independent-client checks"
        );
        None
    };
    let report = json!({"valid":true,"output":output,"manifestDigest":digest,"converted":conversion,"received":verification,"authorization":{"writerA":writer_a,"writerB":writer_b,"reader":reader_access,"readerPull":true,"readerPushDenied":true,"crossRepositoryDenied":true,"expiredTokenDenied":true,"invalidTokenDenied":true},"independentClient":independent,"registryStores":[output.join("company-a"),output.join("company-b")]});
    fs::write(
        output.join("demo-report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}
