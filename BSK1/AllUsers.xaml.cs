using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace BSK1
{
   
    public partial class AllUsers : Window
    {


        private ListBox _allUsers;

        public AllUsers(ListBox users)
        {
            InitializeComponent();
            listBox.SelectionMode = SelectionMode.Multiple;
            listBox.ItemsSource = Users.loadUsers();
            _allUsers = users;
        }


        private void button_Click(object sender, RoutedEventArgs e)
        {
            foreach (Users item in listBox.SelectedItems)
            {
                if (!_allUsers.Items.Cast<Users>().Contains(item))
                {
                    _allUsers.Items.Add(item);
                }

                this.Close();
            }
        }
    }
}
