# Preserve state addresses from the original demo. Changed AWS names/settings
# may still require replacement; always review the plan for an existing stack.
moved {
  from = aws_db_subnet_group.dap_edu
  to   = aws_db_subnet_group.demo
}

moved {
  from = aws_db_parameter_group.dap_education
  to   = aws_db_parameter_group.demo
}

moved {
  from = aws_db_instance.dap_education
  to   = aws_db_instance.demo
}
