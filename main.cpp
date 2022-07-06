//
// Created by root on 6/7/22.
//纯属蛋疼,添加恶意访问ssh黑名单.
//C++版本
//v1.0 bug暂没清楚，后续版本陆续添加白名单模式,自定义参数模式,等等.
// 最重要的是添加服务器模式,多个服务器同时更新恶意访问ip，或者白名单模式.
//By:iSandy
//
#include <iostream>
#include <string>
#include <fstream>
#include <regex>
#include <set>

#define hosts "/etc/hosts.deny"
using namespace std;

//返回文件打开内容
vector<string> readfile(const string& path = "/root/1.txt") {
    fstream fs;
    fs.open(path, ios::in);
    string str;
    if(!fs.is_open()) {
        cout << "erro!";
    }
    vector<string> file ;
    while (getline(fs, str, '\n')){
        file.push_back(str);
    }
    fs.close();
    return file;
}

//追加模式写入/etc/hosts.deny,只接受被Banip。后面可以引入接口处理
void addfile(const string& st) {
    ofstream ofs;
    ofs.open(hosts, ios::app);
    string str = "sshd:"+st+"\n";
    ofs << str;
    ofs.close();
}

//检测文件是否存在
bool file_path(const string& path) {
    ifstream ifs;
    ifs.open(path, ios::in);
    if (ifs.is_open()) {
        ifs.close();
        return true;
    } else{
        return false;
    }

}

//退出程序前处理的命令
void ex_system() {
    system("rm /tmp/hosts.deny");
    system("rm /tmp/lastb.txt");
    system("service ssh restart");
}

int main() {
    if (file_path("/tmp/hosts.deny")) {system("rm /tmp/hosts.deny");}
    if (file_path("/tmp/lastb.txt")) { system("rm /tmp/lastb.txt");}
    system("cp /etc/hosts.deny /tmp/hosts.deny");
    system("lastb > /tmp/lastb.txt");
    vector<string> lastb = readfile("/tmp/lastb.txt");
    const regex re(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
    smatch ma;
    vector<string> lastb_ip;
    for (const string& str: lastb) {
        if (regex_search(str, ma, re)) {
            lastb_ip.push_back(ma[0]);
        }
        //筛选重复IP
        set<string>s(lastb_ip.begin(), lastb_ip.end());
        lastb_ip.assign(s.begin(), s.end());
    }
    if (lastb_ip.empty()) {
        cout << "暂无发现列表有恶意访问IP" << endl;
        ex_system();
        exit(0);
    }
    vector<string> hostsIp = readfile("/tmp/hosts.deny");
    vector<string> hosts_ip;
    int num = 0;
    for (const string& str: hostsIp) {
        //num > 16则是sshd开头的行数，这里是Ubuntu18.04，后期需另添加函数处理不同系统的hosts.deny的备注行数
        if (regex_search(str, ma, re)) {
            hosts_ip.push_back(ma[0]);
        }
    }
    //如果hosts.deny空，则直接添加。
    if (hosts_ip.empty()) {
        cout << "hosts.deny is Null" << endl;
        for (const string& str: lastb_ip) {
            addfile(str);
        }
        ex_system();
        cout << "Done!" << endl;
        exit(0);
    }
    vector<string> newadd_ip; //更新后的IP容器；2022-6-9 15:14:48更新,方便添加后打印
    for (const string& s1: lastb_ip) {
        //对比/tmp/lastb.txt与/tmp/hosts.deny,筛选不同IP添加到/etc/hosts.deny
        if (std::find(hosts_ip.begin(), hosts_ip.end(), s1) == hosts_ip.end()) {
            addfile(s1);
            newadd_ip.push_back(s1);
            num = num +1;
        }
    }
    if (!newadd_ip.empty()) {
        cout << "累计更新:" << endl;
        for (const string& s: newadd_ip) {
            cout << s << endl;
        }
    }
    if (num == 0) {
        cout << "没有可更新ip" << endl;
    }
    ex_system();
    exit(0);
}