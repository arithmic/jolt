use std::{fs::{File, OpenOptions}, io::Write};

use super::link_opening_combiners::Fqq;

pub fn create_file_for_opening_combiners(){
            // ======= file handling ==========
            let input_json = format!(
                r#"{{  
                "linkingstuff":
                    {{ "openingcombiners": 
                        {{ "bytecodecombiners": {{ "rho": [
            "# 
            );
            let input_file_path = "input_link.json";
    
            let mut input_file = File::create(input_file_path).expect("Failed to create input.json");
            input_file
                .write_all(input_json.as_bytes())
                .expect("Failed to write to input.json");
            println!("Input JSON file created successfully.");
            
            // ======= file handling end ==========
}

pub fn file_add_comma_in_between(){
            // ======= file handling ==========
            let input_json = format!(
                                r#" ,
                            "# 
            );
            
            let input_file_path = "input_link.json";

            let mut input_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(input_file_path)
            .expect("Failed to open input.json");
            input_file
                .write_all(input_json.as_bytes())
                .expect("Failed to write to input.json");
    
            // ======= file handling end ==========
}

pub fn close_brackets_in_file_for_each_opening_combiners(){
            let input_json = format!(
                r#" ]}}
            "# 
        );

        let input_file_path = "input_link.json";

        let mut input_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(input_file_path)
        .expect("Failed to open input.json");
        input_file
            .write_all(input_json.as_bytes())
            .expect("Failed to write to input.json");
}

pub fn open_brackets_in_file_for_each_opening_combiners(input_str: &str){
    let input_json = format!(
    r#" ,
            {:?}: {{ "rho": [
"#, input_str
);

let input_file_path = "input_link.json";

let mut input_file = OpenOptions::new()
.append(true)
.create(true)
.open(input_file_path)
.expect("Failed to open input.json");
input_file
    .write_all(input_json.as_bytes())
    .expect("Failed to write to input.json");
}

pub fn close_last_brackets_in_file_for_combiners(){
    let input_json = format!(
    r#" }},
"# 
);

let input_file_path = "input_link.json";

let mut input_file = OpenOptions::new()
.append(true)
.create(true)
.open(input_file_path)
.expect("Failed to open input.json");
input_file
    .write_all(input_json.as_bytes())
    .expect("Failed to write to input.json");
}

pub fn open_hyperkzg_in_file(input: Fqq){
    let input_json = format!(
    r#" "hyperkzgverifieradvice": {{
            "r": {:?}
    "#, input
    );

let input_file_path = "input_link.json";

let mut input_file = OpenOptions::new()
.append(true)
.create(true)
.open(input_file_path)
.expect("Failed to open input.json");
input_file
    .write_all(input_json.as_bytes())
    .expect("Failed to write to input.json");
}

pub fn open_hyperkzg_components_in_file(input_str: &str, input: Fqq){
    let input_json = format!(
    r#" ,
            {:?}:
            {:?}    
    "#, input_str, input
    );

let input_file_path = "input_link.json";

let mut input_file = OpenOptions::new()
.append(true)
.create(true)
.open(input_file_path)
.expect("Failed to open input.json");
input_file
    .write_all(input_json.as_bytes())
    .expect("Failed to write to input.json");
}

pub fn close_brackets_in_file_for_each_opening_combiners_spartan(){
    let input_json = format!(
        r#" }}
    "# 
);

let input_file_path = "input_link.json";

let mut input_file = OpenOptions::new()
.append(true)
.create(true)
.open(input_file_path)
.expect("Failed to open input.json");
input_file
    .write_all(input_json.as_bytes())
    .expect("Failed to write to input.json");
}

pub fn open_brackets_in_file_for_each_opening_combiners_spartan(input_str: &str){
let input_json = format!(
r#" ,
    {:?}: {{ "rho":
"#, input_str
);

let input_file_path = "input_link.json";

let mut input_file = OpenOptions::new()
.append(true)
.create(true)
.open(input_file_path)
.expect("Failed to open input.json");
input_file
.write_all(input_json.as_bytes())
.expect("Failed to write to input.json");
}

pub fn close_brackets_in_file_for_each_opening_combiners_coeff(){
        let input_json = format!(
            r#"
        "# 
        );

        let input_file_path = "input_link.json";

        let mut input_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(input_file_path)
        .expect("Failed to open input.json");
        input_file
            .write_all(input_json.as_bytes())
            .expect("Failed to write to input.json");
}

pub fn open_brackets_in_file_for_each_opening_combiners_coeff(input_str: &str){
        let input_json = format!(
        r#" ,
            {:?}:
        "#, input_str
        );

        let input_file_path = "input_link.json";

        let mut input_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(input_file_path)
        .expect("Failed to open input.json");
        input_file
        .write_all(input_json.as_bytes())
        .expect("Failed to write to input.json");
}