import sys
import frida

#입력명령어 : python C:\Users\User\Desktop\210527.py com.meitu.makeup
#패지키 이름 : com.meitu.makeupcore.activity
#클래스 이름 : MTBaseActivity
#함수 이름 : B1
#변수 이름 : vb


# def on_message(message, data):
#     if message['type'] == 'send':
#         print(message['payload'])
#     else:
#         print(message)

def multiLineInput():
    multi_line_str = ""
    while True:
        line_str = input(">")
        if line_str == "":
            break
        else:
            multi_line_str += line_str + "\n"
    return multi_line_str


def calSpaceNum(code):
    space_num = 0
    for char in code:
        if char != " ":
            break
        elif char == " ":
            space_num += 1
    # print("space_num : ", space_num)
    return space_num


def processMethodCode(method_code, variable_name):
    # print(method_code)
    new_method_code = ""
    param_code = method_code[method_code.find("(")+1:method_code.find(")")]
    line_codes = method_code.split("\n")
    space_num = calSpaceNum(line_codes[1])

    for index, line_code in enumerate(line_codes[1:-2]):
        print("디버깅 --- ", index)
        if index == len(line_codes[1:-2])-1:
            print("디버깅!!!", index)
            print("콘솔 삽입")
            new_method_code += "\t" + "console.log(" + variable_name + ");\n"
            # new_method_code += "\t" + "send(" + variable_name + ");\n"
        if space_num < 8:
            print("디버깅??? ", index)
            new_method_code +=  ("\t" + line_code[space_num:] + "\n")
        elif space_num == 8:
            print("디버깅$$$$ ", index)
            new_method_code +=  (line_code + "\n")
        else:
            print("디버깅 &&&& ", index)
            new_method_code +=  (line_code[space_num-8:] + "\n")
        print("디버깅 @@@@ ", index)
    return (new_method_code, param_code)

def processImportCode(import_code):
    # print(import_code)
    importDic = {}
    line_codes = import_code.split("\n")

    for line_code in line_codes[:-1]:
        importDic[line_code[line_code.rfind(".")+1:-1]] = line_code[line_code.find(" ")+1:-1]
    return importDic

def extractFridaType(param_code, import_dic, java_frida_type_dic):
    param_list = param_code.split(",")
    new_params = ""
    new_param_types = ""
    for index, param in enumerate(param_list):
        input_type = param[:param.find(" ")]
        if input_type in import_dic:
            if "[]" in input_type: # object array
                frida_type = "[L" + import_dic[input_type]
            else:
                frida_type = import_dic[input_type]
        elif input_type in java_frida_type_dic:
            frida_type = java_frida_type_dic[input_type]
        else:
            print("param_code : ", param_code)
            if param_code != "":
            # print("param : ", param)
            # print("input_type : ", input_type)
            # print("frida_type : ", frida_type)
                print("일치하는 타입 없음.")
                exit()
            return "", ""

        variable_name = param[param.find(" ") + 1:]
        if index != len(param_list) - 1:
            new_params += variable_name + ","
            new_param_types += "\"" + frida_type + "\","
            # print("new_param_types : ", new_param_types)
        else:
            new_params += variable_name
            new_param_types += "\"" + frida_type + "\""


        #variable_name = param[param.find(" ")+1:]
        #if index != len(param_list)-1:
        #    new_params += variable_name + ","
        #    new_param_types +=  frida_type + ","
        #    # print("new_param_types : ", new_param_types)
        #else:
        #    new_params += variable_name
        #    new_param_types += frida_type

            #print(new_params);

    return new_param_types, new_params

PACKAGE_NAME = input("패키지 이름(ex. uk.rossmarks.fridalab) : \n") #
CLASS_NAME = input("클래스 이름(ex. challenge_01) : \n")
FUNCTION_NAME = input("함수 이름(ex. getChall01Int) : \n")
VARIABLE_NAME = input("출력하고 싶은 값(ex. 변수 이름, 함수 호출문) : \n")

print("임포트 코드 : \n")
IMPORT_CODE = multiLineInput()
import_dic = processImportCode(IMPORT_CODE)


print("메소드 코드 : \n")
NEW_METHOD_CODE, PARAM_CODE = processMethodCode(multiLineInput(), VARIABLE_NAME)



java_frida_type_dic = {
    "int" : "int",
    "byte" : "byte",
    "short" : "short",
    "long" : "long",
    "float" : "float",
    "double" : "double",
    "char" : "char",
    "int[]" : "[I",
    "byte[]" : "[B",
    "short[]" : "[S",
    "long[]" : "[J",
    "float[]" : "[F",
    "double[]" : "[D",
    "char[]" : "[C",
}

PARAM_TYPES, PARAM = extractFridaType(PARAM_CODE, import_dic, java_frida_type_dic)

# NEW_METHOD_CODE = "<%=" + NEW_METHOD_CODE + "%>"

param = {
    "PACKAGE_NAME" : PACKAGE_NAME, 
    "CLASS_NAME" : CLASS_NAME, 
    "FUNCTION_NAME" : FUNCTION_NAME, 
    "VARIABLE_NAME" : VARIABLE_NAME, 
    "PARAM_TYPES" : PARAM_TYPES,
    "PARAM" : PARAM,
    "METHOD_CODE" : NEW_METHOD_CODE
}


jscode = """
var targetClass = "%(PACKAGE_NAME)s" + "." + "%(CLASS_NAME)s";
var targetMethod = "%(FUNCTION_NAME)s";

function traceMethod(targetClass,targetMethod) {   

    console.log("패키지.클래스명 : " + targetClass);
    //send("패키지.클래스명 : " + targetClass);
    console.log("함수명 : " + targetMethod);
    // send("함수명 : " + targetMethod);
           
    var hook_class = Java.use(targetClass);                       //hook = <class: com.mwr.dz.models.EndpointManager> 형식으로 클래스를 변환
    hook_class[targetMethod].overload(%(PARAM_TYPES)s).implementation = function(%(PARAM)s) {    //함수 재작성
        console.warn("*** entered " + targetMethod);
     

%(METHOD_CODE)s

        var retval = this[targetMethod].apply(this, arguments); 
        return retval;




    }        
}

setTimeout(function() {          // avoid java.lang.ClassNotFoundException
	Java.perform(function() {

        // console.log("스크립트 코드 정상 실행됨");
        // send("스크립트 코드 정상 실행됨");
        traceMethod(targetClass,targetMethod);    //보고싶은 함수명
	});   	
}, 0);
"""

#%(METHOD_CODE)s
#send("*** entered " + targetMethod);

print(jscode % param)

process = frida.get_usb_device(timeout=10).attach(sys.argv[1])  # timeout=10    ##USB 장치에서 크롬 프로세스를 연결
script = process.create_script(jscode % param)                           #스크립트 코드(jscode)를 frida에서 사용할 수 있도록 생성
#script.on('message', on_message)                               #프리다 스크립트에서 보낸 메세지를 처리할 콜백 함수(on_message)를 설정
script.load()                                                    #생성한 스크립트를 로드
sys.stdin.read()                                                 #스크립트가 동작전에 종료되는 문제 예방
